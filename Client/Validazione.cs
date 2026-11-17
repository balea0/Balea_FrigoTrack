
using System.Text.Json;
using Json.Schema;

public static class Validazione
{
    // Controlla un messaggio usando il JSON Schema indicato
    public static string? Controlla(
        string messaggio,
        string nomeSchema = "telemetry.schema.json")
    {
        string percorso = Path.Combine(
            AppContext.BaseDirectory,
            "schemas",
            nomeSchema
        );

        // Verifica che lo schema esista
        if (!File.Exists(percorso))
        {
            return "Schema non trovato: " + nomeSchema;
        }

        try
        {
            // Carica lo schema
            string testoSchema = File.ReadAllText(percorso);
            JsonSchema schema = JsonSchema.FromText(testoSchema);

            // Legge il messaggio JSON
            using JsonDocument documento =
                JsonDocument.Parse(messaggio);

            // Esegue la validazione
            var risultato = schema.Evaluate(
                documento.RootElement,
                new EvaluationOptions
                {
                    OutputFormat = OutputFormat.List,
                    RequireFormatValidation = true
                }
            );

            if (risultato.IsValid)
            {
                return null;
            }

            return "Messaggio non valido secondo lo schema: "
                + nomeSchema;
        }
        catch (JsonException)
        {
            return "Formato JSON non valido";
        }
    }
}
