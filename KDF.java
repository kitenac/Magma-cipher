
// key deriving function for Magma

public class KDF {
    
    public static byte[][] get_round_keys(byte[] key) {
        
        // DWORD - 32 bits - length of round key and also int
        int i, j;
        byte[][] keys = new byte[32][4];

        // first 8 sub keys - just 4byte slices of initial key
        for (i = 0; i < 8; ++i)
            for (j = 0; j < 4; ++j)   
                keys[i][j] = key[4*i + j];
        
        // another 16 subkeys - are duplicating first 8 subkeys again and again (8+8=16)
        for (i = 8; i < 24; ++i)
            keys[i] = keys[i%8]; 
        
        // and the last group of 8 subkeys are in reversed order (in compare with first 8 subkeys)
        for (i = 24; i < 32; ++i)
            keys[i] = keys[7 - i%8];

        return keys;
    }



    public static void Verify(){
        byte[] key = B_tool.hexStringToByteArray("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        byte[][] keys = KDF.get_round_keys(key);

        System.out.println("Here u can see that KDF is working as planed - see A.2.3 https://tc26.ru/standard/gost/GOST_R_3412-2015.pdf" + "\nkey to derive: "+ B_tool.byteArrayToHexString(key));
        int i = 1;
        for (byte[] key_i : keys){
            System.out.println( i + ". | " + B_tool.byteArrayToHexString(key_i) );
            i++;
        }
    }
    
}
