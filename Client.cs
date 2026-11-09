
using System.Numerics;
using System.Net.Http.Json;
using System.Text.Json;

// ========================================
// AVVIO DEL CLIENT
// ========================================

HttpClient client = new();

string indirizzoServer = "http://localhost:5000";

Console.WriteLine("AVVIO FRIGOTRACK");


// ========================================
// 1. HANDSHAKE DIFFIE-HELLMAN
// ========================================

Console.WriteLine("\nHANDSHAKE");

// Parametri Diffie-Hellman a 2048 bit
BigInteger p = DiffieHellman.P;
BigInteger g = DiffieHellman.G;

// Segreto casuale del Client
BigInteger a = DiffieHellman.GeneraSegreto();

// Chiave pubblica del Client
BigInteger A = BigInteger.ModPow(g, a, p);

// Prepara la richiesta
var richiestaHandshake = new
{
    p = p.ToString(),
    g = g.ToString(),
    A = A.ToString()
};

// Mantiene le lettere maiuscole nel JSON
JsonSerializerOptions opzioniJson = new()
{
    PropertyNamingPolicy = null
};

// Invia l'handshake
HttpResponseMessage rispostaHandshake =
    await client.PostAsJsonAsync(
        indirizzoServer + "/api/handshake",
        richiestaHandshake,
        opzioniJson
    );

if (!rispostaHandshake.IsSuccessStatusCode)
{
    Console.WriteLine("Errore durante l'handshake");

    Console.WriteLine(
        "HTTP " + (int)rispostaHandshake.StatusCode
    );

    Console.WriteLine(
        await rispostaHandshake.Content.ReadAsStringAsync()
    );

    Console.ReadLine();
    return;
}

// Legge la risposta
HandshakeResponse? dati =
    await rispostaHandshake.Content
        .ReadFromJsonAsync<HandshakeResponse>();

if (dati == null ||
    !Guid.TryParse(dati.session_id, out _) ||
    !BigInteger.TryParse(dati.B, out BigInteger B))
{
    Console.WriteLine("Risposta handshake non valida");
    Console.ReadLine();
    return;
}

// Controlla la chiave pubblica del Server
if (!DiffieHellman.ChiavePubblicaValida(B))
{
    Console.WriteLine("Chiave pubblica del Server non valida");
    Console.ReadLine();
    return;
}

// Calcola il segreto condiviso
BigInteger K = BigInteger.ModPow(B, a, p);

string session_id = dati.session_id;

Console.WriteLine("Handshake completato");
Console.WriteLine("Sessione: " + session_id);


// ========================================
// 2. TEST MISURA NON VALIDA - HTTP 400
// ========================================

Console.WriteLine("\nTEST MISURA NON VALIDA");

// La temperatura 55 supera il massimo previsto di 40
string misuraNonValida = JsonSerializer.Serialize(new
{
    sensor_id = "CELLA-BG-007",
    timestamp = DateTimeOffset.UtcNow.ToString("O"),
    cargo_type = "pharma",
    temperature_c = 55.0
});

// Cifra la misura senza validarla sul Client
// In questo modo controlliamo il Server
var (testoTest, tagTest) =
    Cifratura.Cifra(misuraNonValida, K);

// Prepara la busta cifrata
Busta bustaTest = new(
    session_id,
    testoTest,
    tagTest
);

// Invia la misura non valida
HttpResponseMessage rispostaTestMisura =
    await client.PostAsJsonAsync(
        indirizzoServer + "/api/telemetry",
        bustaTest
    );

Console.WriteLine(
    "HTTP " + (int)rispostaTestMisura.StatusCode
);

// Controlla che il Server restituisca HTTP 400
if ((int)rispostaTestMisura.StatusCode == 400)
{
    Busta? erroreRicevuto =
        await rispostaTestMisura.Content
            .ReadFromJsonAsync<Busta>();

    if (erroreRicevuto != null)
    {
        // Decifra il messaggio di errore
        string erroreDecifrato = Cifratura.Decifra(
            erroreRicevuto.ciphertext,
            erroreRicevuto.tag,
            K
        );

        Console.WriteLine(erroreDecifrato);
        Console.WriteLine("TEST SUPERATO");
    }
    else
    {
        Console.WriteLine("TEST NON SUPERATO");
    }
}
else
{
    Console.WriteLine("TEST NON SUPERATO");
}


// ========================================
// 3. PREPARAZIONE DEI SENSORI
// ========================================

var sensori = new[]
{
    new
    {
        sensor_id = "CELLA-BG-007",
        cargo_type = "pharma",
        temperaturaBase = 9.0
    },

    new
    {
        sensor_id = "CELLA-MI-008",
        cargo_type = "food",
        temperaturaBase = 5.2
    },

    new
    {
        sensor_id = "CELLA-CO-009",
        cargo_type = "frozen",
        temperaturaBase = -18.5
    }
};


// ========================================
// 4. INVIO DELLE MISURE
// ========================================

for (int ciclo = 1; ciclo <= 3; ciclo++)
{
    Console.WriteLine("\nCICLO " + ciclo);

    foreach (var sensore in sensori)
    {
        // Variazione casuale della temperatura
        double variazione =
            Random.Shared.Next(-5, 6) / 10.0;

        double temperatura = Math.Round(
            sensore.temperaturaBase + variazione,
            1
        );

        // Prepara la misura
        var misura = new
        {
            sensor_id = sensore.sensor_id,
            timestamp = DateTimeOffset.UtcNow.ToString("O"),
            cargo_type = sensore.cargo_type,
            temperature_c = temperatura,
            humidity = 55,
            battery = 87
        };

        string jsonMisura =
            JsonSerializer.Serialize(misura);

        // Valida la misura
        string? errore = Validazione.Controlla(
            jsonMisura,
            "telemetry.schema.json"
        );

        if (errore != null)
        {
            Console.WriteLine(
                sensore.sensor_id + " | Errore: " + errore
            );

            continue;
        }

        // Cifra la misura
        var (ciphertext, tag) =
            Cifratura.Cifra(jsonMisura, K);

        Busta busta = new(
            session_id,
            ciphertext,
            tag
        );

        // Invia la misura
        HttpResponseMessage risposta =
            await client.PostAsJsonAsync(
                indirizzoServer + "/api/telemetry",
                busta
            );

        if (!risposta.IsSuccessStatusCode)
        {
            Console.WriteLine(
                sensore.sensor_id +
                " | Errore HTTP " +
                (int)risposta.StatusCode
            );

            Console.WriteLine(
                await risposta.Content.ReadAsStringAsync()
            );

            continue;
        }

        // Legge la risposta cifrata
        Busta? bustaRisposta =
            await risposta.Content.ReadFromJsonAsync<Busta>();

        if (bustaRisposta == null)
        {
            Console.WriteLine(
                sensore.sensor_id + " | Risposta non valida"
            );

            continue;
        }

        // Decifra la conferma
        string conferma = Cifratura.Decifra(
            bustaRisposta.ciphertext,
            bustaRisposta.tag,
            K
        );

        using JsonDocument documento =
            JsonDocument.Parse(conferma);

        bool allarme = documento.RootElement
            .GetProperty("alarm")
            .GetBoolean();

        if (allarme)
        {
            Console.WriteLine(
                "ALLARME! " +
                sensore.sensor_id +
                " | " +
                temperatura +
                " °C | Fuori limite"
            );
        }
        else
        {
            Console.WriteLine(
                sensore.sensor_id +
                " | " +
                temperatura +
                " °C | Inviata"
            );
        }
    }

    // Attende cinque secondi tra i cicli
    if (ciclo < 3)
    {
        Console.WriteLine("Attesa di 5 secondi...");
        await Task.Delay(5000);
    }
}


// ========================================
// 5. CONSULTAZIONE DELLE MISURE
// ========================================

Console.WriteLine("\nCONSULTAZIONE MISURE");

// Richiede le misure del primo sensore
var richiestaMisure = new
{
    sensor_id = "CELLA-BG-007",
    from = DateTimeOffset.UtcNow
        .AddDays(-1).ToString("O"),
    to = DateTimeOffset.UtcNow
        .AddMinutes(1).ToString("O")
};

string jsonRichiestaMisure =
    JsonSerializer.Serialize(richiestaMisure);

// Valida la richiesta
string? erroreRichiestaMisure =
    Validazione.Controlla(
        jsonRichiestaMisure,
        "readings-request.schema.json"
    );

if (erroreRichiestaMisure != null)
{
    Console.WriteLine(
        "Errore richiesta misure: " +
        erroreRichiestaMisure
    );

    Console.ReadLine();
    return;
}

// Cifra la richiesta
var (testoMisure, tagMisure) =
    Cifratura.Cifra(jsonRichiestaMisure, K);

Busta bustaMisure = new(
    session_id,
    testoMisure,
    tagMisure
);

// Invia la richiesta
HttpResponseMessage rispostaMisure =
    await client.PostAsJsonAsync(
        indirizzoServer + "/api/readings",
        bustaMisure
    );

if (rispostaMisure.IsSuccessStatusCode)
{
    Busta? bustaRispostaMisure =
        await rispostaMisure.Content
            .ReadFromJsonAsync<Busta>();

    if (bustaRispostaMisure != null)
    {
        // Decifra la risposta
        string jsonMisure = Cifratura.Decifra(
            bustaRispostaMisure.ciphertext,
            bustaRispostaMisure.tag,
            K
        );

        using JsonDocument documentoMisure =
            JsonDocument.Parse(jsonMisure);

        JsonElement elencoMisure =
            documentoMisure.RootElement
                .GetProperty("readings");

        Console.WriteLine(
            "Misure trovate: " +
            elencoMisure.GetArrayLength()
        );

        foreach (JsonElement misura in
                 elencoMisure.EnumerateArray())
        {
            string id = misura
                .GetProperty("sensor_id")
                .GetString()!;

            string data = misura
                .GetProperty("timestamp")
                .GetString()!;

            double temperatura = misura
                .GetProperty("temperature_c")
                .GetDouble();

            Console.WriteLine(
                id + " | " +
                data + " | " +
                temperatura + " °C"
            );
        }
    }
}
else
{
    Console.WriteLine(
        "Errore consultazione: HTTP " +
        (int)rispostaMisure.StatusCode
    );

    Console.WriteLine(
        await rispostaMisure.Content.ReadAsStringAsync()
    );
}


// ========================================
// 6. CHIUSURA DELLA SESSIONE
// ========================================

Console.WriteLine("\nCHIUSURA SESSIONE");

var richiestaChiusura = new
{
    action = "close"
};

string jsonChiusura =
    JsonSerializer.Serialize(richiestaChiusura);

// Valida la richiesta di chiusura
string? erroreChiusura = Validazione.Controlla(
    jsonChiusura,
    "close-request.schema.json"
);

if (erroreChiusura != null)
{
    Console.WriteLine(
        "Errore richiesta chiusura: " +
        erroreChiusura
    );

    Console.ReadLine();
    return;
}

// Cifra la richiesta
var (testoChiusura, tagChiusura) =
    Cifratura.Cifra(jsonChiusura, K);

Busta bustaChiusura = new(
    session_id,
    testoChiusura,
    tagChiusura
);

// Invia la chiusura
HttpResponseMessage rispostaChiusura =
    await client.PostAsJsonAsync(
        indirizzoServer + "/api/close",
        bustaChiusura
    );

if (rispostaChiusura.IsSuccessStatusCode)
{
    Busta? bustaRispostaChiusura =
        await rispostaChiusura.Content
            .ReadFromJsonAsync<Busta>();

    if (bustaRispostaChiusura != null)
    {
        // Decifra la conferma
        string confermaChiusura =
            Cifratura.Decifra(
                bustaRispostaChiusura.ciphertext,
                bustaRispostaChiusura.tag,
                K
            );

        using JsonDocument documentoChiusura =
            JsonDocument.Parse(confermaChiusura);

        bool chiusa = documentoChiusura.RootElement
            .GetProperty("closed")
            .GetBoolean();

        if (chiusa)
        {
            Console.WriteLine(
                "Sessione chiusa correttamente"
            );
        }
    }
}
else
{
    Console.WriteLine(
        "Errore chiusura: HTTP " +
        (int)rispostaChiusura.StatusCode
    );
}


// ========================================
// 7. TEST SESSIONE ELIMINATA - HTTP 401
// ========================================

Console.WriteLine("\nVERIFICA SESSIONE ELIMINATA");

// Riprova a usare la sessione chiusa
HttpResponseMessage rispostaSessione =
    await client.PostAsJsonAsync(
        indirizzoServer + "/api/readings",
        bustaMisure
    );

if ((int)rispostaSessione.StatusCode == 401)
{
    Console.WriteLine(
        "Test riuscito: sessione non più valida (HTTP 401)"
    );
}
else
{
    Console.WriteLine(
        "Risposta inattesa: HTTP " +
        (int)rispostaSessione.StatusCode
    );
}


// ========================================
// FINE DEL PROGRAMMA
// ========================================

Console.WriteLine("\nSimulazione completata");

Console.WriteLine("\nPremi INVIO per terminare...");
Console.ReadLine();


// ========================================
// CLASSI DEI MESSAGGI
// ========================================

public record HandshakeResponse(
    string session_id,
    string B
);

public record Busta(
    string session_id,
    string ciphertext,
    string tag
);
