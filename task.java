import java.util.*;
import java.security.SecureRandom;
import java.security.Key;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;	
		
class RockPaperScissors {
	public static String bytesToHex(byte[] bytes) {
		StringBuilder sb = new StringBuilder();
		for (byte b : bytes) sb.append(String.format("%02X", b));
		return sb.toString();
	}

	public static <T> boolean hasDuplicate(Iterable<T> all) {
    	Set<T> set = new HashSet<T>();
		for (T each: all) if (!set.add(each)) return true;
    	return false;
	}

	public static boolean contains(String[] args, String s) {
    	for (String arg: args) {
    		if (s.equals(arg))
    			return true;		
    	}
		return false;
	}

	private class User {
		private Scanner input;

		public User() {
			input = new Scanner(System.in);			
		}

		public String getMove(String[] args) {
			System.out.print("Available moves:");
			for(String arg: args) {
				System.out.print("\n| " + arg);
			} 
	      	System.out.print("\n| Enter 0 for exit\n" +
	      		"\nEnter your move: ");
	      	String userInput = input.nextLine();
		    if (contains(args, userInput))
		    	return userInput;
		    if (userInput.equals("0"))
    			System.exit(0);
    		return getMove(args);
		}
	}

	private class Computer {
		public String getMove(String[] args) {
			SecureRandom ranGen = new SecureRandom();
			Integer index = ranGen.nextInt(args.length);
			return args[index];
		}
	}

	public static void compareMoves(String[] args, Integer x, Integer y) {
		Integer n = args.length;
		if ((x - y) % n == 0)
			System.out.println("Draw.");
		else if ((((x - y + n) % n + 1) % 2) == 1)
			System.out.println("You win!");
		else
			System.out.println("Computer win.");	
	}

	public User user;
	public Computer computer;

	public RockPaperScissors() {
		user = new User();
		computer = new Computer();	
	}

	public Key generateKey() throws NoSuchAlgorithmException {
		SecureRandom ranGen = new SecureRandom();
		byte[] aesKey = new byte[16];
		ranGen.nextBytes(aesKey);

		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
     	keyGen.init(ranGen);
    	return keyGen.generateKey();
	}

	public String getKey(Key key) {
		byte[] encodedBytes = key.getEncoded();
		return bytesToHex(encodedBytes);	
	}

	public byte[] generateHmac (Key key, String computerMove) throws NoSuchAlgorithmException, InvalidKeyException {
		Mac mac = Mac.getInstance("HmacSHA256");
	    mac.init(key);
	    byte[] bytes = computerMove.getBytes();      
	    return mac.doFinal(bytes);
	}

	public void startGame(String[] args) throws NoSuchAlgorithmException, InvalidKeyException {
		if (args.length >= 3 && args.length % 2 != 0 && !hasDuplicate(Arrays.asList(args))) {
		    while(true) {
		    	Key key = generateKey();
				String computerMove = computer.getMove(args);
				byte[] HMAC = generateHmac(key, computerMove);
		    	System.out.println("\nHMAC: " + bytesToHex(HMAC));
		    	String userMove = user.getMove(args);
	    		System.out.println("Your move: " + userMove);
	    		System.out.println("Computer move: " + computerMove);
	    		compareMoves(args, Arrays.asList(args).indexOf(userMove), Arrays.asList(args).indexOf(computerMove));
	    		System.out.println("\nHMAC key: " + getKey(key));
		    }	
		}
		else {
			System.out.println("Input error: you must enter at least three non-repeating moves. For example:\n" + 
				"rock paper scissors\n" +
				"1 2 3 4 5 6 7 8 9");
		}
	}
 
	public static void main(String[] args) throws Exception {
		RockPaperScissors game = new RockPaperScissors();
		game.startGame(args);	
	}  
} 
