
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

public class Cifratura
{
    // Cifra un messaggio utilizzando il segreto condiviso
    public static (string, string) Cifra(string messaggio, BigInteger K)
    {
        // Ricava una chiave AES di 32 byte dal segreto K
        byte[] chiave = SHA256.HashData(
            K.ToByteArray(isUnsigned: true, isBigEndian: true)
        );

        // Converte il messaggio in byte
        byte[] dati = Encoding.UTF8.GetBytes(messaggio);

        // Genera un numero casuale per questa cifratura
        byte[] nonce = RandomNumberGenerator.GetBytes(12);

        // Prepara gli array per il risultato
        byte[] cifrato = new byte[dati.Length];
        byte[] tag = new byte[16];

        // Cifra il messaggio
        using AesGcm aes = new AesGcm(chiave, 16);
        aes.Encrypt(nonce, dati, cifrato, tag);

        // Unisce nonce e messaggio cifrato
        byte[] risultato = new byte[nonce.Length + cifrato.Length];

        Array.Copy(nonce, 0, risultato, 0, nonce.Length);
        Array.Copy(cifrato, 0, risultato, nonce.Length, cifrato.Length);

        // Restituisce ciphertext e tag in Base64
        return (
            Convert.ToBase64String(risultato),
            Convert.ToBase64String(tag)
        );
    }


    // Decifra un messaggio ricevuto dal server
    public static string Decifra(string ciphertext, string tagBase64, BigInteger K)
    {
        // Ricava la chiave AES dal segreto condiviso
        byte[] chiave = SHA256.HashData(
            K.ToByteArray(isUnsigned: true, isBigEndian: true)
        );

        // Converte i dati Base64 in byte
        byte[] dati = Convert.FromBase64String(ciphertext);
        byte[] tag = Convert.FromBase64String(tagBase64);

        // Controlla la lunghezza dei dati
        if (dati.Length < 12 || tag.Length != 16)
        {
            throw new CryptographicException("Dati cifrati non validi");
        }

        // Estrae il nonce dai primi 12 byte
        byte[] nonce = new byte[12];
        Array.Copy(dati, 0, nonce, 0, 12);

        // Estrae il messaggio cifrato
        byte[] cifrato = new byte[dati.Length - 12];
        Array.Copy(dati, 12, cifrato, 0, cifrato.Length);

        // Prepara lo spazio per il messaggio originale
        byte[] originale = new byte[cifrato.Length];

        // Decifra il messaggio e verifica il tag
        using AesGcm aes = new AesGcm(chiave, 16);
        aes.Decrypt(nonce, cifrato, tag, originale);

        // Converte il messaggio originale in testo
        return Encoding.UTF8.GetString(originale);
    }

}
