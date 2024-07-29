import java.math.BigInteger;
import java.util.Random;

import javax.crypto.Cipher;

public class Magma implements OFB.CipherAlg {
    
    byte[][] keys;
    
    public Magma(byte[] key){
        this.keys = KDF.get_round_keys(key);
        B_tool.ANIHILATE(key, "initial key");
    }

    byte[] get_key(int i){ return this.keys[i]; }


    // permutations: pi_0 - pi_7:
    static int[][] per_tbl = {
        {1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2},
        {8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7},
        {5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0},
        {7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12},
        {12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11},
        {11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0},
        {6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15},
        {12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1}
    };


    // t - permutation transform
    // half_block - 4bytes = 32bits
    public static byte[] t(byte[] half_block){

        //System.out.println("Half block: " + B_tool.byteArrayToHexString(half_block));
        byte[] res = new byte[4];

        int perm_i = 0;
        int i = 0;

        for (byte BYTE : half_block){

            int r_half = BYTE & 0x0f;
            int l_half = (BYTE & 0xf0) >> 4;

            res[i] = (byte) ( per_tbl[perm_i][l_half] << 4 | (per_tbl[perm_i+1][r_half] ) );

            i+=1;
            perm_i+=2;
        }

        return res;    
    }





    // t ((a + b) in Z/2^32) with <<< 11 after
    public static byte[] g_k(byte[] half_block, byte [] key_i){
        
        long a = B_tool.DWORD_to_int(half_block);
        long b = B_tool.DWORD_to_int(key_i);
        long pow = (long) Math.pow(2, 32);

        // 1. (a + b) in Z/2^32
        long sum = (a % pow) + (b % pow);
 
        //System.out.println(a + " + " + b + " % " + pow + " = " + sum);

        byte[] sumByteArray = B_tool.int_to_DWORD(sum);

        // 2. t(sum)
        byte[] Res = Magma.t(sumByteArray);

        // 3. t <<< 11 - cycle rot 
        long res = B_tool.DWORD_to_int(Res);
        long absent = res >> 21;  // bits that vanishes after << 11 
        res <<= 11;

        res |= absent; // return absent part to the start

        return B_tool.int_to_DWORD(res);
    }


    // cipher rounds: 1-31,  G[k](a1, a0) = (a0,  g[k](a0) ⊕ a1)
    //  (dword, dword) ---> (dword, dword)
    public byte[][] G_k(byte[] a_1, byte[] a_0, int i){
        byte[][] pair = new byte[2][4];
        pair[0] = a_0;
        pair[1] = g_k(a_0, get_key(i)) ;
        pair[1] = B_tool.XOR_DWORDs(pair[1], a_1);

        //System.out.println(B_tool.byteArrayToHexString(pair[0]) + " | " + B_tool.byteArrayToHexString(pair[1]));
        return pair;
    }


    // last cipher round: 32,  G*[k](a1, a0) = (g[k](a0) ⊕ a1) || a0
    //   (dword, dword) ---> qword (8bytes=64bits=block_Size)
    public byte[] G_last(byte[] a_1, byte[] a_0, int i_th){
        byte[] result = new byte[8];

        byte[] l_half = g_k(a_0, get_key(i_th));
        l_half = B_tool.XOR_DWORDs(l_half, a_1);
        for(int i=0; i<8; ++i) // res = left_half || a0  
           result[i] = i < 4 ? l_half[i] : a_0[i%4];  
        
        B_tool.ANIHILATE_2x(keys, "\nround keys", false); 
        //System.out.println("\n round keys are now:\n ");   
        //for (byte[] key_i : keys) System.out.println(B_tool.byteArrayToHexString(key_i));
        return result;
    }


    

    // PT blcok --> blocks, block = (a1, a0),   round G_last[K32]G[K31]…G[K2]G[K1](a1, a0)
    public byte[] encrypt(byte[] block){
        // split block in two parts:
        byte[][] pair = new byte[2][4];
        System.arraycopy(block, 0, pair[0], 0, 4);
        System.arraycopy(block, 4, pair[1], 0, 4); 

        // 1-31 rounds
        for (int i=0; i<31; ++i)
            pair = G_k(pair[0], pair[1], i);
        
        // 32-th round 
        return G_last(pair[0], pair[1], 31);
    }


    public byte[] decrypt(byte[] block){
        // split block in two parts:
        byte[][] pair = new byte[2][4];
        System.arraycopy(block, 0, pair[0], 0, 4);
        System.arraycopy(block, 4, pair[1], 0, 4); 

        // 1-31 rounds 
        for (int i=31; i>0; --i)
            pair = G_k(pair[0], pair[1], i);
        
        // 32-th round 
        return G_last(pair[0], pair[1], 0);
    }


    

    public class Unsupported_mode extends Exception {
        public Unsupported_mode(String message) {
            super(message);
        }
    }
    

    // "Simple " encryption/decryption mode - useful as subsystem in other cipher modes (in OFB - for crypting IV) 
    // PT and CT are named here for case when we use mode="encrypt", and vise versa for mode = "decrypt"   
    public byte[] in_row(byte[] PT, String mode){
        byte[] CT = new byte[PT.length]; 
        byte[][] blocks = B_tool.slice_to_s_Bytes(PT, 8);
        int i = 0;
        if (mode == "encrypt") 
            for (byte[] block : blocks) { 
                 System.arraycopy(encrypt(block), 0, CT, i*8, 8); i++; }
        else if (mode == "decrypt")
            for (byte[] block : blocks) { System.arraycopy(decrypt(block), 0, CT, i*8, 8); i++; }
        else{
            try {
                throw new Unsupported_mode("Unsupported mode: " + mode);
            } catch (Unsupported_mode e) {
                System.out.println("Caught exception: " + e.getMessage());
            }
        }
    
        return CT;  //if mode = "decrypt" - returns PT - decripted CT
     }

}