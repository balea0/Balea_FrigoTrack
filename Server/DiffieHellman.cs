
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;

public static class DiffieHellman
{
    // Numero primo standard a 2048 bit (RFC 3526, gruppo 14)
    private const string PrimoEsadecimale =
        "FFFFFFFFFFFFFFFFC90FDAA22168C234" +
        "C4C6628B80DC1CD129024E088A67CC74" +
        "020BBEA63B139B22514A08798E3404DD" +
        "EF9519B3CD3A431B302B0A6DF25F1437" +
        "4FE1356D6D51C245E485B576625E7EC6" +
        "F44C42E9A637ED6B0BFF5CB6F406B7ED" +
        "EE386BFB5A899FA5AE9F24117C4B1FE6" +
        "49286651ECE45B3DC2007CB8A163BF05" +
        "98DA48361C55D39A69163FA8FD24CF5F" +
        "83655D23DCA3AD961C62F356208552BB" +
        "9ED529077096966D670C354E4ABC9804" +
        "F1746C08CA18217C32905E462E36CE3B" +
        "E39E772C180E86039B2783A2EC07A28F" +
        "B5C55DF06F4C52C9DE2BCBF695581718" +
        "3995497CEA956AE515D2261898FA0510" +
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF";

    // Parametri pubblici condivisi
    public static readonly BigInteger P = BigInteger.Parse(
        "0" + PrimoEsadecimale,
        NumberStyles.AllowHexSpecifier
    );

    public static readonly BigInteger G = new BigInteger(2);

    // Genera un segreto casuale di 256 bit
    public static BigInteger GeneraSegreto()
    {
        byte[] bytes = RandomNumberGenerator.GetBytes(32);

        return new BigInteger(
            bytes,
            isUnsigned: true,
            isBigEndian: true
        ) + 2;
    }

    // Controlla che una chiave pubblica sia accettabile
    public static bool ChiavePubblicaValida(BigInteger valore)
    {
        if (valore < 2 || valore > P - 2)
        {
            return false;
        }

        // Controlla l'appartenenza al sottogruppo previsto
        BigInteger q = (P - 1) / 2;

        return BigInteger.ModPow(valore, q, P) == 1;
    }
}
