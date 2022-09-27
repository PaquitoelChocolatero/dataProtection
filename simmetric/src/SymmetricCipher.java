import java.util.Arrays;

public class SymmetricCipher {

	byte[] byteKey;
	SymmetricEncryption s;
	SymmetricEncryption d;
	
	// Initialization Vector (fixed)
	
	final byte[] iv = {0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,0x31,0x32,0x33,0x34,0x35,0x36};
	// final byte[] iv = new byte[] { (byte)49, (byte)50, (byte)51, (byte)52, (byte)53, (byte)54, 
	// 	(byte)55, (byte)56, (byte)57, (byte)48, (byte)49, (byte)50, (byte)51, (byte)52,
	// 	(byte)53, (byte)54};

    /*************************************************************************************/
	/* Constructor method */
    /*************************************************************************************/
	public SymmetricCipher() {
	}

    /*************************************************************************************/
	/* Method to encrypt using AES/CBC/PKCS5 */
    /*************************************************************************************/
	public byte[] encryptCBC (byte[] input, byte[] byteKey) throws Exception {
		byte[] myIV = iv.clone();
		s = new SymmetricEncryption(byteKey);
		
		byte[] ciphertext = null;
			
		int padding = s.AES_BLOCK_SIZE - (input.length % s.AES_BLOCK_SIZE);
		byte[] pInput = Arrays.copyOf(input, input.length + padding);
		// Generate the plaintext with padding
		
		for(int i = 0; i < padding; i++){
			pInput[input.length + i] = (byte) padding;
		}
		
		ciphertext = pInput.clone();
		// Generate the ciphertext
		for(int i = 0; i < pInput.length / s.AES_BLOCK_SIZE; i++) {
			byte[] xorInput = Arrays.copyOfRange(pInput, i * s.AES_BLOCK_SIZE, i * s.AES_BLOCK_SIZE + s.AES_BLOCK_SIZE);

			for(int j = 0; j < xorInput.length; j++) {
				xorInput[j] = (byte) (xorInput[j] ^ myIV[j]);
			}
			byte[] rellenar = s.encryptBlock(xorInput);
			for(int j = 0; j < rellenar.length; j++) {
				ciphertext[(i * s.AES_BLOCK_SIZE) + j] = rellenar[j];
			}
			myIV = rellenar.clone();
		}
		
		
		return ciphertext;
	}
	
	/*************************************************************************************/
	/* Method to decrypt using AES/CBC/PKCS5 */
    /*************************************************************************************/
	
	
	public byte[] decryptCBC (byte[] input, byte[] byteKey) throws Exception {
		byte[] myIV = iv.clone();
		d = new SymmetricEncryption(byteKey);
		byte [] finalplaintext = input.clone();
		
		// Generate the plaintext

		for(int i = 0; i < input.length / d.AES_BLOCK_SIZE; i++) {
			byte[] outBlock = Arrays.copyOfRange(input, i * 16, i * 16 + 16);
			byte[] xorOutput = d.decryptBlock(outBlock);
			for(int j = 0; j < xorOutput.length; j++) {
				finalplaintext[(i * d.AES_BLOCK_SIZE) + j] = (byte) (xorOutput[j] ^ myIV[j]);
			}
			myIV = outBlock.clone();
		}	

				// Eliminate the padding
		
		byte last = finalplaintext[finalplaintext.length - 1];
		int i = 1;
		while (last == finalplaintext[finalplaintext.length - i]) {
			i++;
		}
		finalplaintext = Arrays.copyOf(finalplaintext, finalplaintext.length - i + 1);
		
		return finalplaintext;
	}
	
}

