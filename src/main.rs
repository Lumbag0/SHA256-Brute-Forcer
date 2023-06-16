use std::env;
use std::error::Error;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Write;
use sha2::{Sha256, Digest};


const SHA256_HEX_LENGTH: usize = 64;
fn main() -> Result<(), Box<dyn Error>> 
{
    let argument: Vec<String> = env::args().collect(); //user input collection
    if argument.len() != 4 // error handling for correct syntax
    {
        println!("Syntax: <wordlist> <hash> <option>");
        return Ok(());
    }

    let hash = argument[2].trim();
    let modded_hash = hex::decode(hash).expect("failed to collect hash"); //modifies the hash for comparing
    
    if hash.len() != SHA256_HEX_LENGTH //error handling for argument 2
    {
        return Err("SHA256 hash provided is not SHA256".into());
    }


    let wordlist = File::open(&argument[1])?; //opens wordlist provided 
    let reader = BufReader::new(&wordlist); //improves speeds
    

    for line in reader.lines()
    {
        let line = match line { //error handling
            Ok(l) => l,
            Err(io) if io.kind() == io::ErrorKind::InvalidData => break, //detects bad unicode
            Err(e) => return Err(Box::new(e)) //if any other error is detected
        };

        //magic SHA256 
        let password = line.trim();
        let mut hasher = Sha256::new();
        hasher.update(password);
        let result = hasher.finalize();


        if modded_hash == result.as_slice()
        {
            println!("Password Found! {}", &password);
            println!("writing to file passwords.txt");
            let content = format!("{}:{}", hash, password); //formatting hash and found password together
            let mut file = OpenOptions::new() //create file and allowing it to be appended too
                .create(true)
                .append(true)
                .open("passwords.txt")?;
            file.write_all(content.as_bytes())?; //write content to file
            file.write_all("\n".as_bytes())?; //adds new line to file
            return Ok(());
        }
        
    }
    println!("impossible, perhaps the archives are incomplete"); //if password isnt found in wordlist

    Ok(())
}
