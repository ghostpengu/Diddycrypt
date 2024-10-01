use aes::{Aes128, BlockEncrypt, BlockDecrypt, NewBlockCipher};
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use sha2::{Sha256, Digest};
use rand::{Rng, rngs::OsRng};
use hex;
use std::io::{self, Write, Read};
use std::fs::File;
use std::path::Path;
use std::fs;
use zip::write::FileOptions;
use zip::ZipWriter;
use zip::read::ZipArchive;
use std::io::Cursor;

const DIDDY:&str = "                               ......
                             .,;ii;:;;;;;:,.
                       ...,::;;;;;:;;:;;;::::,,.
                    .:;;;ii;:;::::::,,,,,:::::;;,.
                   .ii;;;;;:,:::,:::::,:,,,,:::::::.
                 ,;irsrX22Ar;:;:::;;;:::;;iri;:,::::,.
               .:rXMGGHHHM352AAXsXAXXssXAA222AXXXsi:::.
              ,issMSGHHMh35222222AA2222222222255552Ai::,.
             ,;ir5HHMhh3522AAAAAAAAA22222222222222252;:::.
          .,:iiisMMh3352AAAAAAAAAAAA22222222222222225r::::.
          .iriiishh352AXssXXXAAAAA222222222AAAAAA2222X;::::
           :i;i;s552AXXsssssXXAAAA2A2222222AAAAAAAAAAA;::::,.
          ,;i;;;s22AAXXXXXXAAAA2222222222222AAAAAAAAAAr::::;. .......
         .;;::;:rXsssXAAAAAA2225555222555522222A22AAAAs;::::.       ...
        .::::::;sssXA2AAAAAA25555355555555555222222AXXXi::::.         ...
        .;,:::iXXX25siiirrrrrsXX2555552AssXXXsXXsrsXXXXs;:::,           ..
         ::,,;sAXAA;::::::::::;irXA2AXXr;;:::::;;iiisXXsi:::.
         ,:,::AAXsi:;;;;iirrriiirrsXAXsrriirrri;;irrrsssi:,,.
       .,,:::i2Xsi;;;::;::;sXssrirX22Asssrr;;;;riiirrsss;,,:.
       :AAsr;X2Xsiii;;iXiir22rrrirX22Assss2s;iA5iirsssXsi:rAX.
       ,i;iriA22AsssssrrrsXsssrirsA222XXsssXXXXXXXAAXXXsrsAXr.
       .riri;A255A22AAXXXAAAXsrrrsA2222AAAAXAAAAAAAAAAXsrs2A;           ..
        :ss;XAAA22AA22222222AXrsXAA2252AA222222222222AXsrX2s.           ..
         issssXsXssXXA222222AsX222225552A22222555222AXsrX55;
         :2XXsXssrrrsXAA2552XX52AA23h55255555555222AXsrrX22.
          iAriXXsriirrXA2252Xrri:;sXXsrirX2555552AXXsrrsAX,
          .s2rsXsriiirsXA252AsrrrrXsXXsssX255552AAXssrsX32
           .,.:XrriiirrsXAAAAAXsssXXssXXA222222AAXssrss;:,
              ,rrriiiirsXXXssrssXXXAAXXXssAA22AXXssrssX;
               irri;iiirssiiirrrrrrXAssssssrXAAXXsrrssXr
               :rii;iiirriii;;is222553AsrirrrXAXXsrsssAs
               ,rii;;;irrrrrrrXA55333h352XXXXsXXsrrrssAr
               .sri;;;;irrsrrrsXA2533352AAAAXssrrrrssXAr
               .rsi;:::;;irrriirrrrrrsssXAAAXssrrssssXXX.
                ,iii;;;;;iirrsssssiirsAAAAXXXssrssrrssX9s
                 :i;;;;;;;iiiirirrrrrsXXXXXsrrrssrrrsXS@B;
                .;ii;;;;:,,,::,:,:::::;;;;;;::rrrrrs3B@@@G.......
                ihii;;;;::,,,,,,::,,,:,,,:,,:irrrs5#@@@@@Bi:::;;;:.
                s&hi;;;;;;::,,.,,,,,,,,,,:;irrrAM9@@@@@@@9i::::::;;::,...
             .,;AB&#5riiiii;::,,,,,:::;irrrrX3S&@@@@@@@@@h:::::::::;;;;;;;
           .:sX;XBB&&#hArririiirsssssssssX5GB@@@@@@@@@@@Br:::::::::::::;;;
     ..,::;rXXr,2B#9B&@&#MArrrrrssssrrX3GB@@@@@@@@@@@@@@M:::::::::::::::::
.,:;iiiriiisXr:,53:isA5MG99SM5XssssX5G&@@@BSHh52AAXXh9@Bs,::::::::::::::::
rrrii;;;;;iss;::;:::,,,,,:;rXA22AAMB@@#3Xi:,..,,,,:::M@S;:::::::::::::::::
i;;;;;::;;iri:,::::::::::::,,,,:;;isAr:,,,::::::,,;;;#@5,:::::::::::::::::
:::::;:;;;ii;:,::::::::::::::;::;;:::,:::::,::,,,:i;X&G:::::::::::::::::::
::::;;;;;ii;:,,::;;,.,:::::,,:,::,:::::,,,,,,,,,:;i;GBr,::::::::::::::::::
::;;;;;;;i;;:,:r,;i;:,::::::::,:::;;:,::::,,,,,:;i;2@5,:::::::::::::::::::
:;::;;;;;;;::,:5::;;;::::;;;;:;H###SH:,:;:,,:::;iii#H:,:::::::::::::::::::
:::::;;;;;;:::,MA.:;;;;;;;::::3BB&&&#;.,::::::::;:hBi,:::::::::::::::,,,::
::::;;;:;;;;:,:HSr:;;;;;;;:::X#9B&@&9X.,,::::::::5@5,:::::::::::::,,,:::::
::::::;;::;::,;S9S;:;;;;;:::rG9B@@@&BH::::::::;:5BG:::::::::::::::::::::::
;;:::::::;;::,iS99M:;;;;:::rGB&@@@@@&9h:,::::;:3&9X,:::::::::::::::::::::,
::::::::;;:::,iGSS92,:::::sS&@@@&@&&&B9Hr,::;,3@Bh::::::::::::::::::::::,:
::::::::;;:::,rS#9B953A;r3#&@@@@@@@@@&&B9hs;rh&&#r::::::::::::::::::::::::
:::::::::::::,sS##9BBB9GS##BBBBBB999B999###GSBB#5:;;;;;;::::::::::::::::::

WELCOME TO DIDDY CRYPT

use 'start' to initialize diddy
use 'lock' to crypt folder
use 'unlock' to uncypt folder

";

type Aes128Cbc = Cbc<Aes128, Pkcs7>;

fn generate_key(password: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(password);
    hasher.update(salt);
    hasher.finalize().to_vec()
}

fn encrypt(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Aes128Cbc::new_from_slices(key, iv).unwrap();
    cipher.encrypt_vec(plaintext)
}

fn zip_folder<P: AsRef<Path>>(folder_path: P) -> Vec<u8> {
    let mut buffer = Vec::new();
    {
        let folder_path = folder_path.as_ref();
        let mut zip_writer = ZipWriter::new(Cursor::new(&mut buffer));

        for entry in fs::read_dir(folder_path).expect("Failed to read directory") {
            let entry = entry.expect("Failed to get directory entry");
            let path = entry.path();

            if path.is_file() {
                let mut file = File::open(&path).expect("Failed to open file");
                let options = FileOptions::default();
                zip_writer
                    .start_file(path.file_name().unwrap().to_str().unwrap(), options)
                    .unwrap();

                io::copy(&mut file, &mut zip_writer).expect("Failed to copy file content");
            }
        }

        zip_writer.finish().unwrap();
    }

    buffer
}

fn decrypt(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Aes128Cbc::new_from_slices(key, iv).unwrap();
    cipher.decrypt_vec(ciphertext).unwrap()
}

fn unzip_folder(data: &[u8], output_folder: &Path) {
    let cursor = Cursor::new(data);
    let mut archive = ZipArchive::new(cursor).expect("Failed to open zip archive");

    for i in 0..archive.len() {
        let mut file = archive.by_index(i).unwrap();
        let output_file_path = output_folder.join(file.name());

        let mut output_file = File::create(&output_file_path).expect("Failed to create output file");
        io::copy(&mut file, &mut output_file).expect("Failed to extract file");
    }
}

fn save_encrypted_file(filename: &str, encrypted_data: &[u8], salt: &[u8], iv: &[u8]) {
    let mut file = File::create(filename).expect("Failed to create encrypted file");
    file.write_all(salt).expect("Failed to write salt");
    file.write_all(iv).expect("Failed to write IV");
    file.write_all(encrypted_data).expect("Failed to write encrypted data");
    fs::remove_dir_all("data").unwrap();
}

fn read_encrypted_file(filename: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut file = File::open(filename).expect("Failed to open encrypted file");
    let mut salt = vec![0u8; 32];
    let mut iv = vec![0u8; 16];
    let mut encrypted_data = Vec::new();

    file.read_exact(&mut salt).expect("Failed to read salt");
    file.read_exact(&mut iv).expect("Failed to read IV");
    file.read_to_end(&mut encrypted_data).expect("Failed to read encrypted data");

    (salt, iv, encrypted_data)
}

pub fn input(text: Option<&str>) -> String {
    match text {
        Some(t) => {
            print!("{}", t);
            io::stdout().flush().unwrap();
        }
        None => {}
    }
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read input");

    input.trim().to_string()
}

fn console() {
    match input(Some(">")).as_str(){
        "lock" =>{
            print!("Enter your password for encryption: ");
            io::stdout().flush().unwrap();
        
            let mut password_input = String::new();
            io::stdin()
                .read_line(&mut password_input)
                .expect("Failed to read line");
        
            let password = password_input.trim().as_bytes();
        
            // Generate a random salt
            let mut salt = [0u8; 32];
            OsRng.fill(&mut salt);
        
            // Generate a key from the password and salt
            let key = generate_key(password, &salt);
        
            // Initialization vector (IV) - should be random for each encryption
            let mut iv = [0u8; 16];
            OsRng.fill(&mut iv);
        
            // Specify the folder to zip
            let folder_path = "data";
            let zipped_data = zip_folder(folder_path);
        
            // Encrypt the zipped folder data
            let encrypted_data = encrypt(&zipped_data, &key[..16], &iv);
        
            // Save encrypted data to a file
            save_encrypted_file("encrypted_data.diddy", &encrypted_data, &salt, &iv);
            println!("Encrypted data saved to 'encrypted_data.diddy'");
        

        },
        "start"=>{
            fs::create_dir("data").unwrap()
        }
        "unlock" =>{
                 // Prompt the user for a password for decryption
                 print!("Enter your password for decryption: ");
                 io::stdout().flush().unwrap();
     
                 let mut password_input_decrypt = String::new();
                 io::stdin()
                     .read_line(&mut password_input_decrypt)
                     .expect("Failed to read line");
     
                 let password_decrypt = password_input_decrypt.trim().as_bytes();
     
                 // Read the encrypted data from the file
                 let (salt_read, iv_read, encrypted_data_read) = read_encrypted_file("encrypted_data.diddy");
     
                 // Regenerate the key from the decryption password and the same salt
                 let key_decrypt = generate_key(password_decrypt, &salt_read);
     
                 // Decrypt the encrypted folder data
                 let decrypted_data = decrypt(&encrypted_data_read, &key_decrypt[..16], &iv_read);
     
                 // Unzip the decrypted data to a specified output folder
                 let output_folder = Path::new("data");
                 fs::create_dir_all(output_folder).expect("Failed to create output directory");
                 unzip_folder(&decrypted_data, output_folder);
                 fs::remove_file("encrypted_data.diddy").unwrap();

        },
        _ =>{
           

        }
    }
    
    
}

fn main() {
    println!("{}",DIDDY);
    loop {
        console();
    }
   
}
