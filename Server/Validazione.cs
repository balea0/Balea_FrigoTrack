
using System.Text.Json;
using Json.Schema;

public class Validazione
{
    // Controlla un messaggio utilizzando lo schema indicato
    public static string? Controlla(
        string messaggio,
        string nomeSchema = "telemetry.schema.json")
    {
        // Indica il percorso del file schema
        string percorso = Path.Combine(
            AppContext.BaseDirectory,
            "schemas",
            nomeSchema
        );

        // Legge lo schema dal file
        string testoSchema = File.ReadAllText(percorso);

        // Carica lo schema JSON
        JsonSchema schema = JsonSchema.FromText(testoSchema);

        try
        {
            // Converte il messaggio in JSON
            using JsonDocument documento =
                JsonDocument.Parse(messaggio);

            // Controlla il messaggio con lo schema
            var risultato = schema.Evaluate(
                documento.RootElement,
                new EvaluationOptions
                {
                    OutputFormat = OutputFormat.List,
                    RequireFormatValidation = true
                }
            );

            // Se il messaggio è valido, non restituisce errori
            if (risultato.IsValid)
            {
                return null;
            }

            // Cerca il campo che contiene un errore
            if (risultato.Details != null)
            {
                foreach (var dettaglio in risultato.Details)
                {
                    if (dettaglio.Errors != null)
                    {
                        foreach (var errore in dettaglio.Errors)
                        {
                            return "Campo " +
                                dettaglio.InstanceLocation +
                                ": " + errore.Value;
                        }
                    }
                }
            }

            // Controlla anche gli errori generali
            if (risultato.Errors != null)
            {
                foreach (var errore in risultato.Errors)
                {
                    return "Errore: " + errore.Value;
                }
            }

            return "Messaggio non valido";
        }
        catch (JsonException)
        {
            // Il messaggio non contiene un JSON corretto
            return "Formato JSON non valido";
        }
    }
}
