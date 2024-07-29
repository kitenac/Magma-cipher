import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Random;

public class B_tool {
        // hexstring ---> bytes
        public static byte[] hexStringToByteArray(String hexString) {
            int length = hexString.length();
            byte[] byteArray = new byte[length / 2];
            for (int i = 0; i < length; i += 2) {
                byteArray[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                        + Character.digit(hexString.charAt(i + 1), 16));
            }
            return byteArray;
        }

        // vise versa
        public static String byteArrayToHexString(byte[] array) {
            StringBuilder sb = new StringBuilder();
            for (byte b : array) {
                sb.append(String.format("%02X ", b));
            }
            return sb.toString();
        }

        
        public static long DWORD_to_int(byte[] DWORD){
            // & FFL = long FF - due sign of integer, then << with step 8 from 24=8*3 to 0=8*0 - to form octets of integer
            // we use long and NOT int - bc int is signed - so 1 bit is reserver and it can`t represent all values from {0;2^32-1}
            return 
                        ((DWORD[0] & 0xFFL) << 24) | 
                        ((DWORD[1] & 0xFFL) << 16) | 
                        ((DWORD[2] & 0xFFL) << 8)  | 
                         (DWORD[3] & 0xFFL)        ;
        }
        
        public static byte[] int_to_DWORD(long Int){
            byte[] byteArray = new byte[4];
            
            // reversed order of DWORD_to_int, and putting bytes back to array 
            byteArray[0] = (byte) ((Int >> 24) & 0xFFL);
            byteArray[1] = (byte) ((Int >> 16) & 0xFFL);
            byteArray[2] = (byte) ((Int >> 8)  & 0xFFL);
            byteArray[3] = (byte)  (Int & 0xFFL);        
    
            return byteArray;
        }


        public static long bytes_to_Long(byte[] byteArray) {
            ByteBuffer buffer = ByteBuffer.wrap(byteArray);
            return buffer.getLong();
        }

        public static byte[] long_to_bytes(long value) {
            ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
            buffer.putLong(value);
            return buffer.array();
        }


        public static byte[] XOR_DWORDs(byte[] x, byte[] y){
            byte[] XOR = new byte[4];
            for (int i=0; i<4; ++i)
                XOR[i] = (byte) (x[i] ^ y[i]);
            return XOR;
        }

        public static byte[] XOR_s_Bytes(byte[] x, byte[] y, int s){
            byte[] XOR = new byte[s];
            for (int i=0; i<s; ++i)
                XOR[i] = (byte) (x[i] ^ y[i]);
            return XOR;
        }

        // here we know if extra s-block is needed - when PT.length%s!=0
        public static int know_ammount_of_s_blocks (byte[] PT, int s){
            return (PT.length%s==0) ? PT.length/s : PT.length/s + 1;
        }

        public static long know_ammount_of_s_blocks_ (int PT_length, int s){
            return (PT_length%s==0) ? PT_length/s : PT_length/s + 1;
        }

        // slice PT into s-byte blocks 
        // Limits: if s=8, file must be < 17,3 Gb = 2147483647 * 8 bytes, bc MAX int = 2147483647
        public static byte[][] slice_to_s_Bytes(byte[] PT, int s){
            
            int N = know_ammount_of_s_blocks(PT, s); 

            int i;
            byte[][] blocks = new byte[N][s];   
            //System.out.println("- Got PT of size=" + PT.length +  ".\nMakig " + N + " s-byted blocks...\n\n");
            for (i=0; i<N-1; ++i) 
                System.arraycopy(PT, i*s, blocks[i], 0, s); // fill the blocks

            // last block may be not full - so coppy only PT.length%s
            if (PT.length%s!=0) 
                System.arraycopy(PT, i*s, blocks[i], 0, PT.length%s);
            else
                System.arraycopy(PT, i*s, blocks[i], 0, s);

            return blocks;
        }

        
        public static byte[] merge_s_Bytes(byte[][] blocks, int s){
            byte [] Res = new byte[blocks.length*s];
            int i = 0;
            for (byte[] block: blocks){
                System.arraycopy(block, 0, Res, i*s, s); // put block in result
                i++;
            }
            return Res;
        }


        public static void ANIHILATE(byte[] array, String name){
            Arrays.fill(array, (byte) 0);
            System.out.printf("[clean] %s Successfully errased %s", Management.getDateTime(), name);
        }

        public static void ANIHILATE_2x(byte[][] array, String name, Boolean verbose){
            for (byte[] key : array) 
                Arrays.fill(key, (byte) 0);

            if (verbose) System.out.printf("[clean] %s Successfully errased %s", Management.getDateTime(), name);
        }


        public static void Create_file_of_N_MB(int N) {
            String filePath = N + "mb.test";
            long fileSizeInBytes = 1024 * 1024 * N; // 10 MB

            try {
                File file = new File(filePath);
                RandomAccessFile randomAccessFile = new RandomAccessFile(file, "rw");
                randomAccessFile.setLength(fileSizeInBytes);
                randomAccessFile.close();

            } catch (IOException e) {
                e.printStackTrace();
            }
        }


        public static byte[] gen_bytes(int m){
            byte[] bytes = new byte[m];
            new Random().nextBytes(bytes);
            return bytes;
        }


        public static void Heap_info() {
            Runtime runtime = Runtime.getRuntime();
    
            long heapSize = runtime.totalMemory();
            long heapMaxSize = runtime.maxMemory();
            long heapFreeSize = runtime.freeMemory();
    
            System.out.println("Heap size: " + formatSize(heapSize));
            System.out.println("Heap max size: " + formatSize(heapMaxSize));
            System.out.println("Heap free size: " + formatSize(heapFreeSize));
        }
    
        public static String formatSize(long v) {
            if (v < 1024) return v + " B";
            int z = (63 - Long.numberOfLeadingZeros(v)) / 10;
            return String.format("%.1f %sB", (double) v / (1L << (z * 10)), " KMGTPE".charAt(z));
        }


        // suitble to test values of round functions    
        public static void Verify_Functions(byte [] val, byte [] result){
            System.out.println("\nInput: \n"+ B_tool.byteArrayToHexString(val));
            System.out.println("\nOutput: \n"+ (byteArrayToHexString(result) + "\n\n"));
        }
}
