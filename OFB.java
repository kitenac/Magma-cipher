import java.util.Random;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.zip.CRC32;


public class OFB {

    // =========== interface to be implemented for any object trated as cipher algorithm e.g. Magma
    public interface CipherAlg {
        // single block encryption
        byte[] encrypt(byte[] data);
        byte[] decrypt(byte[] encryptedData); 
        // encrypt/decrypt multiple rows at one time - need for IV encrypting (storing it as plain - to risky)
        byte[] in_row(byte[] PT, String mode); // mode = "encrypt"/"decrypt"
    }



    // =========== parametrs of OFB (static - to be able access them)
    static int s = 6;               // length of PT block
    static int m = 16;              // length of IV and => len of slide-register 

    static int n = 8;          // size of block in bytes for Cipher              
    static CipherAlg Cipher;   // algorithm for gamma generation

    // count start block of real CT - goes after ini_v
    static int start = (m%s!=0) ? (int)(m/s)+1 : (int)(m/s); // 16/6 = 2, but 2 blocks aren`t enough - so add 1 more         

    // OFB OFB_scheme = new OFB(new Magma(k));
    public OFB(CipherAlg Cipher){
        this.Cipher = Cipher;    
    }



    // =========== Functions to obtain INI_vector for crypt/decrypt
    public byte[] gen_INI_v(int m){
        byte[] ini_v = new byte[m];
        new Random().nextBytes(ini_v);
        return ini_v;
    }
    public byte[] restore_INI_v(byte[] CT, int m){
        byte[] ini_v = new byte[m];
        System.arraycopy(CT, 0, ini_v, 0, m); // get cipherd ini_v from start of CT
        ini_v = Cipher.in_row(ini_v, "decrypt");
        return ini_v;
    }

// =========== Some Core functions of OFB mode: work with Register and gamma-handling stuff

// shift register by n: i.e. switch (n) and (m-n) slices
/*            ______________        ______________
             |_n__|__m-n____| ---> |__m-n___|_n___|
*/
    public static void Shift_Register(byte[] Register, byte[] n_){
        System.arraycopy(Register, n-1,  Register, 0, m-n);
        System.arraycopy(Register, n,    n_,       0, n);
    }


    public static byte[] Get_Gamma(byte[] Register, byte[] n_){
        System.arraycopy(Register, 0, n_, 0, n);  // take n msb-bytes of Register in sub register
        return Cipher.encrypt(n_);  // encrypt n msb-bytes - getting gamma
    }

    public static void XOR_block_with_gamma_into_byteArray
     (byte[] block, byte[] gamma, 
      byte[] byteArray, int pos_in_byteArray){    
            System.arraycopy(
            B_tool.XOR_s_Bytes(block, gamma, s), 0, 
            byteArray, pos_in_byteArray, s); 
    }



// =========== Encrypt/Decrypt functions (in fact they also handle PT/CT-slicing and getting IV brfore crypt/decrypt) :

// !!! ALERT, AHCTUNG !!! - remember to store CT - it contains cyphered IV - bc not only key and PT are affect CT - BUT ALSO ini_vector IV
// OFB is logicaly - XOR: crypt and decrypt are same operations - XOR. 
//  Block Cipher here - helps to get pesudo-random gamma for xoring with PT  
//  the only difference in crypt and decrypt is the source of IV for generating gamma: for crypting - it`s random generator, for decrypting - first m bytes of CT, also there is minor differences in -pre and -post processing of inputed CT

    public byte[] encrypt(byte[] PT){    
        byte[][] blocks = B_tool.slice_to_s_Bytes(PT, s);   
        byte[] Register = new byte[m];
        byte[] IV;

        IV = gen_INI_v(m);

        int CT_size = s * (start + B_tool.know_ammount_of_s_blocks(PT, s));
        byte[] CT = new byte[CT_size];  
        System.arraycopy(Cipher.in_row(IV, "encrypt"), 0, CT, 0, m); // put ciphered IV to the start of CT (to have access to decrypt)
        System.arraycopy(IV, 0, Register, 0, m);  // initial state - coppy IV values into Regiser


        // buffer(subregister) for n-part (gamma) of Register:
        /*            ______________
          Register:  |__n__|__m-n___|
         */
        byte[] n_ = new byte[n];
 

        // encrypting all PT
        int i;
        for (i=0; i < blocks.length; ++i){
            n_ = Get_Gamma(Register, n_);  // gamma
            XOR_block_with_gamma_into_byteArray(blocks[i], n_, CT, (i+start)*s);
            Shift_Register(Register, n_);
        }
        
        // truncate CT - to size of PT + size allocated for IV  
        int clean = PT.length + B_tool.know_ammount_of_s_blocks(IV, s)*s;
        byte[] trunc = new byte[clean]; 
        System.arraycopy(CT, 0, trunc, 0, clean);

        return trunc;
    }


    public byte[] decrypt(byte[] CT){

        byte[][] blocks = B_tool.slice_to_s_Bytes(CT, s);   
        byte[] PT = new byte[CT.length-start*s];
        System.arraycopy(CT, start*s, PT, 0, CT.length-start*s);   // skip IV from CT


        byte[] Register = new byte[m];
        byte[] IV;
        IV = restore_INI_v(CT, m);
        System.arraycopy(IV, 0, Register, 0, m);  // initial state - coppy IV values into Regiser


        // buffer(subregister) for n-part (gamma) of Register:
        /*            ______________
          Register:  |__n__|__m-n___|
         */
        byte[] n_ = new byte[n];
 

        // decrypting all blocks exept last
        int i;
        for (i=0; i < blocks.length - start -1; ++i){ 
            n_ = Get_Gamma(Register, n_);  // gamma
            XOR_block_with_gamma_into_byteArray(blocks[i+start], n_, PT, i*s);
            Shift_Register(Register, n_);
        }

        
        // ------ handle last CT block - may be of size r <= s (not every time CT.length%s = 0)
        int r = CT.length%s;  // reminder
        if (CT.length%s == 0) r=s;

        n_ = Get_Gamma(Register, n_);  // gamma
          
        // same "XOR_block_with_gamma_into_byteArray()" - but with size of block = r
        System.arraycopy(
            B_tool.XOR_s_Bytes(blocks[i+start], n_, r), 0, 
            PT, i*s, r); 

        return PT;
    }



        public static void check_integrity_of_program(long Etalon_value_crc){
        String directoryPath = "."; // Current directory 
        
        // Open each .java file in current directory:
        String[] ignore_integrity = {"Management.java"};
        String[] check_integrity = {".java"};

        byte[] all_javaFiles_bytes = Management.get_all_files_bytes(directoryPath, ignore_integrity, check_integrity);

        CRC32 crc32 = new CRC32();
        crc32.update(all_javaFiles_bytes);

        long crcValue = crc32.getValue();
        System.out.print("Checksum: " + crcValue);


        

        if (crcValue != Etalon_value_crc){
            System.out.printf("[FAIL] %s Integrity test of program is failed! - stop doing nasty things with our code :)", Management.getDateTime());
            System.exit(300);
        }
        else{
            System.out.printf("[OK] %s Integrity test of program is passed.\n", Management.getDateTime());
        }
    }

    // check integrity of file each T_sec seconds - works in separate thread so will not affect execution
    public static void start_demon_check_integrity_of_program(long Etalon_crc, int T_sec){
        ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();
        Runnable task = () -> {
            check_integrity_of_program(Etalon_crc);
        };

        executor.scheduleAtFixedRate(task, 0, T_sec, TimeUnit.SECONDS);
        
    }





}
