
using System.Numerics;
using System.Security.Cryptography;
using System.Collections.Concurrent;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.Urls.Add("http://localhost:5000");

// Sessioni attive e chiavi condivise
ConcurrentDictionary<string, BigInteger> sessioni = new();

// File delle misure
string percorsoMisure = Path.Combine(
    app.Environment.ContentRootPath,
    "misure.json"
);

// Protegge gli accessi al file
object bloccoMisure = new();


// ========================================
// 1. HANDSHAKE DIFFIE-HELLMAN
// ========================================

app.MapPost("/api/handshake", (JsonElement datiRicevuti) =>
{
    // Valida il JSON ricevuto
    string? erroreSchema = Validazione.Controlla(
        datiRicevuti.GetRawText(),
        "handshake-request.schema.json"
    );

    if (erroreSchema != null)
    {
        return Results.BadRequest(new
        {
            error = erroreSchema
        });
    }

    // Legge la richiesta
    HandshakeRequest richiesta =
        datiRicevuti.Deserialize<HandshakeRequest>()!;

    // Converte i numeri ricevuti
    if (!BigInteger.TryParse(richiesta.p, out BigInteger p) ||
        !BigInteger.TryParse(richiesta.g, out BigInteger g) ||
        !BigInteger.TryParse(richiesta.A, out BigInteger A))
    {
        return Results.BadRequest(new
        {
            error = "Numeri handshake non validi"
        });
    }

    // NUOVO: accetta soltanto i parametri standard
    if (p != DiffieHellman.P || g != DiffieHellman.G)
    {
        return Results.BadRequest(new
        {
            error = "Parametri Diffie-Hellman non consentiti"
        });
    }

    // NUOVO: verifica la chiave pubblica del Client
    if (!DiffieHellman.ChiavePubblicaValida(A))
    {
        return Results.BadRequest(new
        {
            error = "Chiave pubblica del Client non valida"
        });
    }

    // NUOVO: genera un segreto casuale di 256 bit
    BigInteger b = DiffieHellman.GeneraSegreto();

    // Calcola la chiave pubblica del Server
    BigInteger B = BigInteger.ModPow(
        DiffieHellman.G,
        b,
        DiffieHellman.P
    );

    // Calcola il segreto condiviso
    BigInteger K = BigInteger.ModPow(
        A,
        b,
        DiffieHellman.P
    );

    // Crea la sessione
    string session_id = Guid.NewGuid().ToString();

    // Prepara la risposta
    var rispostaHandshake = new
    {
        session_id,
        B = B.ToString()
    };

    // Valida la risposta
    string jsonRisposta =
        JsonSerializer.Serialize(rispostaHandshake);

    string? erroreRisposta = Validazione.Controlla(
        jsonRisposta,
        "handshake-response.schema.json"
    );

    if (erroreRisposta != null)
    {
        return Results.Problem(
            "Risposta handshake non valida"
        );
    }

    // Memorizza la chiave della sessione
    sessioni[session_id] = K;

    return Results.Ok(rispostaHandshake);
});


// ========================================
// 2. RICEZIONE DELLE MISURE
// ========================================

app.MapPost("/api/telemetry", (JsonElement datiRicevuti) =>
{
    // Valida la busta cifrata
    string? erroreBusta = Validazione.Controlla(
        datiRicevuti.GetRawText(),
        "encrypted-envelope.schema.json"
    );

    if (erroreBusta != null)
    {
        return Results.BadRequest(new
        {
            error = erroreBusta
        });
    }

    Busta richiesta = datiRicevuti.Deserialize<Busta>()!;

    // Controlla i campi ricevuti
    if (string.IsNullOrWhiteSpace(richiesta.session_id) ||
        string.IsNullOrWhiteSpace(richiesta.ciphertext) ||
        string.IsNullOrWhiteSpace(richiesta.tag))
    {
        return Results.BadRequest();
    }

    // Recupera la chiave della sessione
    if (!sessioni.TryGetValue(
        richiesta.session_id,
        out BigInteger K))
    {
        return Results.Unauthorized();
    }

    string messaggio;

    try
    {
        // Decifra la misura
        messaggio = Cifratura.Decifra(
            richiesta.ciphertext,
            richiesta.tag,
            K
        );
    }
    catch (FormatException)
    {
        return Results.BadRequest();
    }
    catch (CryptographicException)
    {
        return Results.BadRequest();
    }

    // Valida la misura decifrata
    string? errore = Validazione.Controlla(
        messaggio,
        "telemetry.schema.json"
    );

    if (errore != null)
    {
        // Prepara l'errore
        string rispostaErrore = JsonSerializer.Serialize(new
        {
            error = errore
        });

        // Valida l'errore
        string? controlloErrore = Validazione.Controlla(
            rispostaErrore,
            "error-response.schema.json"
        );

        if (controlloErrore != null)
        {
            return Results.Problem(
                "Risposta di errore non valida"
            );
        }

        // Cifra l'errore
        var (testo, tagErrore) =
            Cifratura.Cifra(rispostaErrore, K);

        return Results.BadRequest(new
        {
            richiesta.session_id,
            ciphertext = testo,
            tag = tagErrore
        });
    }

    // Legge i dati della misura
    using JsonDocument misuraRicevuta =
        JsonDocument.Parse(messaggio);

    string tipo = misuraRicevuta.RootElement
        .GetProperty("cargo_type").GetString()!;

    double temperatura = misuraRicevuta.RootElement
        .GetProperty("temperature_c").GetDouble();

    // Controlla la temperatura dei farmaci
    bool allarme = tipo == "pharma" &&
                   (temperatura < 2 || temperatura > 8);

    string conferma;

    if (allarme)
    {
        conferma = JsonSerializer.Serialize(new
        {
            ack = true,
            alarm = true,
            message = "Temperatura fuori limite",
            temperature_c = temperatura
        });
    }
    else
    {
        conferma = JsonSerializer.Serialize(new
        {
            ack = true,
            alarm = false
        });
    }

    // Valida la risposta di telemetria
    string? erroreConferma = Validazione.Controlla(
        conferma,
        "telemetry-response.schema.json"
    );

    if (erroreConferma != null)
    {
        return Results.Problem(
            "Risposta telemetria non valida"
        );
    }

    // Salva la misura
    lock (bloccoMisure)
    {
        List<JsonElement> misure = new();

        if (File.Exists(percorsoMisure))
        {
            string contenuto =
                File.ReadAllText(percorsoMisure);

            misure =
                JsonSerializer.Deserialize<List<JsonElement>>(
                    contenuto
                ) ?? new();
        }

        using JsonDocument documento =
            JsonDocument.Parse(messaggio);

        misure.Add(documento.RootElement.Clone());

        File.WriteAllText(
            percorsoMisure,
            JsonSerializer.Serialize(
                misure,
                new JsonSerializerOptions
                {
                    WriteIndented = true
                }
            )
        );
    }

    // Cifra la conferma
    var (ciphertext, tagRisposta) =
        Cifratura.Cifra(conferma, K);

    return Results.Ok(new
    {
        richiesta.session_id,
        ciphertext,
        tag = tagRisposta
    });
});


// ========================================
// 3. CONSULTAZIONE DELLE MISURE
// ========================================

app.MapPost("/api/readings", (JsonElement datiRicevuti) =>
{
    // Valida la busta
    string? erroreBusta = Validazione.Controlla(
        datiRicevuti.GetRawText(),
        "encrypted-envelope.schema.json"
    );

    if (erroreBusta != null)
    {
        return Results.BadRequest(new
        {
            error = erroreBusta
        });
    }

    Busta richiesta = datiRicevuti.Deserialize<Busta>()!;

    // Controlla i campi
    if (string.IsNullOrWhiteSpace(richiesta.session_id) ||
        string.IsNullOrWhiteSpace(richiesta.ciphertext) ||
        string.IsNullOrWhiteSpace(richiesta.tag))
    {
        return Results.BadRequest();
    }

    // Recupera la chiave
    if (!sessioni.TryGetValue(
        richiesta.session_id,
        out BigInteger K))
    {
        return Results.Unauthorized();
    }

    string messaggio;

    try
    {
        // Decifra la richiesta
        messaggio = Cifratura.Decifra(
            richiesta.ciphertext,
            richiesta.tag,
            K
        );
    }
    catch (FormatException)
    {
        return Results.BadRequest();
    }
    catch (CryptographicException)
    {
        return Results.BadRequest();
    }

    // Valida la richiesta
    string? errore = Validazione.Controlla(
        messaggio,
        "readings-request.schema.json"
    );

    if (errore != null)
    {
        string rispostaErrore = JsonSerializer.Serialize(new
        {
            error = errore
        });

        // Valida il messaggio di errore
        string? controlloErrore = Validazione.Controlla(
            rispostaErrore,
            "error-response.schema.json"
        );

        if (controlloErrore != null)
        {
            return Results.Problem(
                "Risposta di errore non valida"
            );
        }

        var (testo, tagErrore) =
            Cifratura.Cifra(rispostaErrore, K);

        return Results.BadRequest(new
        {
            richiesta.session_id,
            ciphertext = testo,
            tag = tagErrore
        });
    }

    // Legge la richiesta
    using JsonDocument documento =
        JsonDocument.Parse(messaggio);

    string sensore = documento.RootElement
        .GetProperty("sensor_id").GetString()!;

    string inizio = documento.RootElement
        .GetProperty("from").GetString()!;

    string fine = documento.RootElement
        .GetProperty("to").GetString()!;

    // Controlla le date
    if (!DateTimeOffset.TryParse(
            inizio, out var dataInizio) ||
        !DateTimeOffset.TryParse(
            fine, out var dataFine) ||
        dataInizio > dataFine)
    {
        string rispostaErrore = JsonSerializer.Serialize(new
        {
            error = "Intervallo di date non valido"
        });

        // Valida l'errore
        string? controlloErrore = Validazione.Controlla(
            rispostaErrore,
            "error-response.schema.json"
        );

        if (controlloErrore != null)
        {
            return Results.Problem(
                "Risposta di errore non valida"
            );
        }

        var (testo, tagErrore) =
            Cifratura.Cifra(rispostaErrore, K);

        return Results.BadRequest(new
        {
            richiesta.session_id,
            ciphertext = testo,
            tag = tagErrore
        });
    }

    // Cerca le misure
    List<JsonElement> trovate = new();

    lock (bloccoMisure)
    {
        if (File.Exists(percorsoMisure))
        {
            string contenuto =
                File.ReadAllText(percorsoMisure);

            List<JsonElement> misure =
                JsonSerializer.Deserialize<List<JsonElement>>(
                    contenuto
                ) ?? new();

            foreach (var misura in misure)
            {
                string id = misura
                    .GetProperty("sensor_id").GetString()!;

                string data = misura
                    .GetProperty("timestamp").GetString()!;

                if (DateTimeOffset.TryParse(
                        data, out var dataMisura) &&
                    id == sensore &&
                    dataMisura >= dataInizio &&
                    dataMisura <= dataFine)
                {
                    trovate.Add(misura);
                }
            }
        }
    }

    // Prepara la risposta
    string risposta = JsonSerializer.Serialize(new
    {
        readings = trovate
    });

    // Valida la risposta
    string? erroreRispostaMisure = Validazione.Controlla(
        risposta,
        "readings-response.schema.json"
    );

    if (erroreRispostaMisure != null)
    {
        return Results.Problem(
            "Risposta consultazione non valida: " +
            erroreRispostaMisure
        );
    }

    // Cifra la risposta
    var (ciphertext, tagRisposta) =
        Cifratura.Cifra(risposta, K);

    return Results.Ok(new
    {
        richiesta.session_id,
        ciphertext,
        tag = tagRisposta
    });
});


// ========================================
// 4. CHIUSURA DELLA SESSIONE
// ========================================

app.MapPost("/api/close", (JsonElement datiRicevuti) =>
{
    // Valida la busta
    string? erroreBusta = Validazione.Controlla(
        datiRicevuti.GetRawText(),
        "encrypted-envelope.schema.json"
    );

    if (erroreBusta != null)
    {
        return Results.BadRequest(new
        {
            error = erroreBusta
        });
    }

    Busta richiesta = datiRicevuti.Deserialize<Busta>()!;

    // Controlla i campi
    if (string.IsNullOrWhiteSpace(richiesta.session_id) ||
        string.IsNullOrWhiteSpace(richiesta.ciphertext) ||
        string.IsNullOrWhiteSpace(richiesta.tag))
    {
        return Results.BadRequest();
    }

    // Recupera la chiave
    if (!sessioni.TryGetValue(
        richiesta.session_id,
        out BigInteger K))
    {
        return Results.Unauthorized();
    }

    string messaggio;

    try
    {
        // Decifra la richiesta
        messaggio = Cifratura.Decifra(
            richiesta.ciphertext,
            richiesta.tag,
            K
        );
    }
    catch (FormatException)
    {
        return Results.BadRequest();
    }
    catch (CryptographicException)
    {
        return Results.BadRequest();
    }

    // Valida la richiesta di chiusura
    string? errore = Validazione.Controlla(
        messaggio,
        "close-request.schema.json"
    );

    if (errore != null)
    {
        string rispostaErrore = JsonSerializer.Serialize(new
        {
            error = errore
        });

        // Valida l'errore
        string? controlloErrore = Validazione.Controlla(
            rispostaErrore,
            "error-response.schema.json"
        );

        if (controlloErrore != null)
        {
            return Results.Problem(
                "Risposta di errore non valida"
            );
        }

        var (testo, tagErrore) =
            Cifratura.Cifra(rispostaErrore, K);

        return Results.BadRequest(new
        {
            richiesta.session_id,
            ciphertext = testo,
            tag = tagErrore
        });
    }

    // Prepara la conferma
    string conferma = JsonSerializer.Serialize(new
    {
        closed = true
    });

    // Valida la conferma
    string? erroreConferma = Validazione.Controlla(
        conferma,
        "close-response.schema.json"
    );

    if (erroreConferma != null)
    {
        return Results.Problem(
            "Risposta chiusura non valida"
        );
    }

    // Cifra la conferma
    var (ciphertext, tagRisposta) =
        Cifratura.Cifra(conferma, K);

    // Elimina la sessione
    if (!sessioni.TryRemove(
        richiesta.session_id,
        out _))
    {
        return Results.Unauthorized();
    }

    return Results.Ok(new
    {
        richiesta.session_id,
        ciphertext,
        tag = tagRisposta
    });
});


// ========================================
// AVVIO DEL SERVER
// ========================================

app.Run();


// ========================================
// CLASSI DEI MESSAGGI
// ========================================

public record HandshakeRequest(
    string p,
    string g,
    string A
);

public record Busta(
    string session_id,
    string ciphertext,
    string tag
);
