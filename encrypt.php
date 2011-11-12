<?php
        // The following is a description of SRP-6 and 6a, the latest versions of SRP:
        // ---------------------------------------------------------------------------
        //   N    A large safe prime (N = 2q+1, where q is prime)
        //        All arithmetic is done modulo N.
        //   g    A generator modulo N
        //   k    Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
        //   s    User's salt
        //   I    Username
        //   p    Cleartext Password
        //   H()  One-way hash function
        //   ^    (Modular) Exponentiation
        //   u    Random scrambling parameter
        //   a,b  Secret ephemeral values
        //   A,B  Public ephemeral values
        //   x    Private key (derived from p and s)
        //   v    Password verifier
        // ---------------------------------------------------------------------------
        // specification: http://srp.stanford.edu/design.html
        // article: http://en.wikipedia.org/wiki/Secure_Remote_Password_protocol
        // contains code from tomrus88 (https://github.com/tomrus88/d3proto/blob/master/Core/SRP.cs
/*
            
			
			var salt = SRP6a.GetRandomBytes(32);
			  public static byte[] GetRandomBytes(int count)
				{
					var rnd = new Random();
					var result = new byte[count];
					rnd.NextBytes(result);
					return result;
				}
            var passwordVerifier = SRP6a.CalculatePasswordVerifierForAccount(email, password, salt)

*/

include_once 'Lib/BigInteger.php';
include_once 'functions.php';

$password   = $_POST['password'];
$email      = $_POST['email'];

// simple email check!
if ( emailCheck($email) )
{
    echo "Email is correct and parsing it to protocol<br>\r\n";
}
else
{ 
    die("Email is wrong!");
}

// $salt is ranmbly number unique for the user
echo "Process Salt unique random 32 bytes<br>";
//$salt = getRAndomByte($email);
$salt = "D857A8E7C5C7EF5202D5A65C69BFB30BC0FA68D957EF24FC8D38A18B2EA16641";  
echo $upsalt = hex2bin($salt)."<br>\r\n";
$saltHex = bin2hex($salt);
//echo $hex;
// N is large safe prime
echo "debug N bigInt <br>\r\n";
$N_packet =  "\xAB\x24\x43\x63\xA9\xC2\xA6\xC3\x3B\x37\xE4\x61\x84\x25\x9F\x8B\x3F\xCB\x8A\x85\x27\xFC\x3D\x87\xBE\xA0\x54\xD2\x38\x5D\x12\xB7\x61\x44\x2E\x83\xFA\xC2\x21\xD9\x10\x9F\xC1\x9F\xEA\x50\xE3\x09\xA6\xE5\x5E\x23\xA7\x77\xEB\x00\xC7\xBA\xBF\xF8\x55\x8A\x0E\x80\x2B\x14\x1A\xA2\xD4\x43\xA9\xD4\xAF\xAD\xB5\xE1\xF5\xAC\xA6\x13\x1C\x69\x78\x64\x0B\x7B\xAF\x9C\xC5\x50\x31\x8A\x23\x08\x01\xA1\xF5\xFE\x31\x32\x7F\xE2\x05\x82\xD6\x0B\xED\x4D\x55\x32\x41\x94\x29\x6F\x55\x7D\xE3\x0F\x77\x19\xE5\x6C\x30\xEB\xDE\xF6\xA7\x86";
$N =  "AB244363A9C2A6C33B37E46184259F8B3FCB8A8527FC3D87BEA054D2385D12B761442E83FAC221D9109FC19FEA50E309A6E55E23A777EB00C7BABFF8558A0E802B141AA2D443A9D4AFADB5E1F5ACA6131C6978640B7BAF9CC550318A230801A1F5FE31327FE20582D60BED4D55324194296F557DE30F7719E56C30EBDEF6A786";
$N_bin = hex2bin($N);
$little_N = unpack("n*",$N_bin);
print_r($little_N);
for($i = count($little_N) ; $i > 0 ; $i--)
{
    $pre_BigN .= pack("v",$little_N[$i]);
}

$bigN =  new Math_BigInteger($pre_BigN,256);
echo "big N may is : <br>\r\n".$bigN."<br>\r\n";	
/*
$a = new Math_BigInteger('94558736629309251206436488916623864910444695865064772352148093707798675228170106115630190094901096401883540229236016599430725894430734991444298272129143681820273859470730877741629279425748927230996376833577406570089078823475120723855492588316592686203439138514838131581023312004481906611790561347740748686507');

echo $a->toBytes(); // outputs chr(65
echo "<br>".$pre_BigN;
*/
echo "<br>\r\n";
//echo $bigN;
	//for($i=0;$i<count($N);$i++)		
		//$N_concat = pack("nvc*",0xAB0x24);
//echo $N;

//Identitysalt is SHA256(users's mail) it is needed to make $pBytes
$identitySalt = hash(sha256,$email,false);
echo "process Identity salt email = ".$email." ASCIIMail = ".ascii_to_hex($email).":<br>\r\n";
echo $identitySalt."<br>\r\n";

// p is hash( identitySalt:password )
$p_string = strtoupper($identitySalt).":".strtoupper($password);
$pBytes = hash(sha256,$p_string,false);
echo "process pBytes = <b>".$p_string."</b> <br> Hex = <b>".ascii_to_hex($p_string)."</b> <br>\r\n";
echo "this is pBytes hash: ".$pBytes."<br>\r\n";

// g is generator modulo N 
echo "debug G BigInt <br>\r\n";
$g = 02;
$g_bin = hex2bin($g);
$g = new Math_BigInteger($g_bin,256);
echo "G may is: ".$g."<br>\r\n";

// x = Hash(s,p)
echo "debug x process <br>\r\n";
$pre_x = $salt.strtoupper($pBytes);
echo "this is Hex of concat x: ".$pre_x."<br>\r\n";;
//echo $out_put=pack("H*",$prova)."<br>";
$bin = (hex2bin($pre_x));
foreach ( str_split($bin) as $char ) {
			$out_put .= ord($char); 
	}

echo "<br>this is bytes of x :<br>".$out_put."<br>\r\n";

$x = hash(sha256,trim($bin),true);
/*$x = encodeBytes($x);
foreach ( str_split($x) as $char ) {
			$out_x .= ord($char); 
	}*/
echo "<b>this is the hashed bytes not equals to hash output of mooege code x: ".$x."</b><br>\r\n";
//echo $hexX = ascii_to_hex($x);
//$x_=hex2bin($x);

echo "<br>\r\n";
$little = unpack("n*",$x);
for($i = count($little) ; $i > 0 ; $i--) {
			$little_x .= pack("v",$little[$i]);
	}

//convert hex hashed X to BigInt
echo "Process calculate BigX :<br>";
$bigX = new Math_BigInteger($little_x,256);
echo $bigX."<br>\r\n";
// calculate v = password verify  v = g^x (computes password verifier) mod N
echo "process doing modPow and generates the password verifier input for database account<br>";
$v = $g->modPow($bigX,$bigN);
echo $v->toBytes();
echo "<br>\r\n";
echo $v->toString();
echo "<br>\r\n";
$little_N = unpack("N*",$v->toBytes());
for($i = count($little_N) ; $i > 0 ; $i--) {
			$final_out .= pack("V",$little_N[$i]);
		
	}
echo "<br>\r\n<b>Final bit string to be insert to db: ".$final_out." </b><br>\r\n<br>\r\n";

echo hex2bin('2D55194F');
/*
    if ($db = sqlite_open('account', 0666, $err)) {
        $q = sqlite_query($db,"INSERT INTO accounts (email,salt,passwordVerifier,userLevel) values ('$email','$salt','$v','0') ",$err);
		if($q) echo "query ok";
		else die($err);
    } else {
        die($err);
    }
*/

try 
{
    /*** connect to SQLite database ***/

    $dbh = new PDO("sqlite:account_.db");
    echo "Handle has been created ...... <br>\r\n<br>\r\n";
	$upsalt = sqlite_escape_string($upsalt);
	$final_out = sqlite_escape_string($final_out);
	$err = $dbh->query("INSERT INTO accounts (id,email,salt,passwordVerifier,userLevel) values ('1','$email','$upsalt','$final_out','0') ");
    if ($err === FALSE)
    {
        print_r($dbh->errorInfo());
        die();
    }
}
catch(PDOException $e)
{
    echo $e->getMessage();
    echo "<br><br>Database -- NOT -- loaded successfully .. ";
    die( "<br><br>Query Closed !!! $error");
} 

echo "<br>\r\n";
$try = "60683445811919773798863222188611761022136228504431938369652346294898676478397934261939039724151966156232748957057177993650136849104605467563890584964858417847082365052362779511433190242910819978604133847570752722998578697919705135525622764497365127716302661789756419292995834780114234244965184704756229098613";
//echo base_convert($try,10,16);

//$try_ = unpack("V*",$try);
//echo hex2bin($v->toHex());
//print_r($try_);

//echo hex2bin('754c');
//print_r($try_);
//require_once 'Lib/base128.php'; 
//foreach( $try_ as $bin)
		$try2 .= chr($bin);
//echo base128_encode($try);;
//$a=base128_encode(9455873662930925120643648891662386491044469586506477235214809370779867522817010611563019009490109640188354022923601659943072589443073499144429827212914368182027385947073087774162927942574892723099637683357740657008907882347512072385549258831659268620343913851483813158102331200448190661179056134774074868650); 
/*foreach( $try_t as $bin)
		$try2 .= pack("H*",$bin);
echo $try2;
echo "<br>";
$try3 = unpack("V*",$try2);
foreach( $try3 as $bin)
		$try4 .= pack("H*",$bin);
echo $try4;
echo pack("H*",$try4); */


// functions moved to dedicated file: functions.php
/* EOF */
?>