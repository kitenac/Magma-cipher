import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;


public class Management {

    public static byte[] get_all_files_bytes(String directoryPath, String[] Ignore_endsWith, String[] Must_endsWith){
        ByteArrayOutputStream byte_stream = new ByteArrayOutputStream();

        try (DirectoryStream<Path> directoryStream = Files.newDirectoryStream(Paths.get(directoryPath))) {
     outerLoop: for (Path filePath : directoryStream) {
                if (Files.isRegularFile(filePath)) {
                    String fileName = filePath.getFileName().toString();
                    
                    // Check BlackList, than whitelist - to select needed files
                    for (String el : Ignore_endsWith)
                        if (fileName.endsWith(el)) continue outerLoop;
                    for (String el : Must_endsWith)
                        if (!fileName.endsWith(el)) continue outerLoop;
                    

                    byte[] bytes = Files.readAllBytes(filePath);
                    byte_stream.write(bytes, 0, bytes.length);

                    //System.out.println(filePath + " current size: " + byte_stream.size());
                }
            }
            
        } catch (IOException e) {
            e.printStackTrace();
        }
        return byte_stream.toByteArray();
    }

    public static String getDateTime(){
        LocalDateTime currentDateTime = LocalDateTime.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
        String formattedDateTime = currentDateTime.format(formatter);

        return formattedDateTime;
    }


    public static void CalcTime(long startTime, long endTime, int MB, String test_n){
        long delta = endTime - startTime;
        // Convert time to minutes and seconds
        long minutes = (delta / 1000) / 60;
        long seconds = (delta / 1000) % 60;

        System.out.println(test_n +  " Time to crypt and decrypt " + MB + "MB: " + minutes + " min " + seconds + " sec");
    }


    public static void Create_files_for_tests(){
        B_tool.Create_file_of_N_MB(1);
        B_tool.Create_file_of_N_MB(100);
        B_tool.Create_file_of_N_MB(6);
    }

    public static void Make_tests(){
        Create_files_for_tests();
        int[] first_test = {1, 100};
        String name;

        byte[] key = B_tool.hexStringToByteArray("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        Magma Cipher_Magma = new Magma(key);
        OFB OFB_scheme = new OFB(Cipher_Magma);

        byte[] PT; byte[] CT;

        // test1
        for (int test: first_test){
            name = test + "mb.test";    
            try {
                Path path = Paths.get(name);
                PT = Files.readAllBytes(path);

                long startTime = System.currentTimeMillis();
                // ========= Test =========
                CT = OFB_scheme.encrypt(PT); // save CT - it has ciphered IV inside - not only key and PT are affect CT - BUT ALSO ini_vector IV
                PT = OFB_scheme.decrypt(CT);
                // ========= Test =========
                long endTime = System.currentTimeMillis();

                CalcTime(startTime, endTime, test, "\n[Test #1] ");

            } catch (IOException e) {
                e.printStackTrace();
            }

        }
        
        int[] test2_steps = {10, 100}; // {10, 100, 1000}

            // test2
            for (int test2: test2_steps){
                name = 6 + "mb.test";    

                // for test 2 - this vars will change each ammmount of blocks
                byte[] key_t2 = B_tool.gen_bytes(32);
                Magma Cipher_Magma_t2 = new Magma(key_t2);
                OFB OFB_scheme_t2 = new OFB(Cipher_Magma_t2);

                
                int blocks = 0;
                long startTime = System.currentTimeMillis();
                // ========= Test =========
                
                try {
                    byte[] test_PT = new byte[test2];
                    Path path = Paths.get(name);
                    byte[] all_PT = Files.readAllBytes(path);
                        
                    for (; blocks*(test2+1) < all_PT.length; ){
                        System.arraycopy(all_PT, blocks*test2, test_PT, 0, test2);
                        blocks++;
                                                        
                        CT = OFB_scheme_t2.encrypt(test_PT); // save CT - it has ciphered IV inside - not only key and PT are affect CT - BUT ALSO ini_vector IV
                        PT = OFB_scheme_t2.decrypt(CT);
                    }
                        
                // ========= Test =========
                long endTime = System.currentTimeMillis();
            
                CalcTime(startTime, endTime, test2, "\n[Test #2] ");
                }
                
                catch (IOException e) {
                    e.printStackTrace();
                }
            }

        
        
    
    }
    

    public static void Shell() {
        int T_sec = 3; // how often to check integrity
        long Etalon_crc = 1277172538;
        OFB.start_demon_check_integrity_of_program(Etalon_crc, T_sec);

        //B_tool.Heap_info();
        Make_tests();

        System.exit(200); // close program
    }


}
