public class Main {


    public static void main(String[] args) {

        Management.Shell();
        
        // ========================= TEST-ZONE ==================
        
        //KDF.Verify(); // +++ KDF:

        // t() +++
        // byte[] half_bl = B_tool.hexStringToByteArray("fdb97531");
        // B_tool.Verify_Functions(half_bl, Magma.t(half_bl));

        // g_k() +++
        // byte[] half_bl2 = B_tool.hexStringToByteArray("fedcba98");
        // byte[] key_i = B_tool.hexStringToByteArray("87654321");

        // B_tool.Verify_Functions(half_bl2, Magma.g_k(half_bl2, key_i));

        // Encryption +++
        // byte[] TestPT = B_tool.hexStringToByteArray("fedcba9876543210");
        // byte[] key = B_tool.hexStringToByteArray("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        // Magma Cipher_Magma = new Magma(key);

        // // block encryption and decryption +++
        //B_tool.Verify_Functions(TestPT, Cipher_Magma.encrypt(TestPT));
        //B_tool.Verify_Functions(Cipher_Magma.encrypt(TestPT), Cipher_Magma.decrypt(Cipher_Magma.encrypt(TestPT)));

        // OFB +++ - Final check
        // byte[] PT = B_tool.hexStringToByteArray("11111111111111110102030405060708091033");
        // OFB OFB_scheme = new OFB(Cipher_Magma); 

        //byte[] CT = OFB_scheme.encrypt(PT); // save CT - it has ciphered IV inside - not only key and PT are affect CT - BUT ALSO ini_vector IV
        //B_tool.Verify_Functions(PT, CT);
        //B_tool.Verify_Functions(CT, OFB_scheme.decrypt(CT));
        

        // ========================= TEST-ZONE ==================

        

    }

}
