<?php
global $env;
// Load environment variables
$env = parse_ini_file('.env');
// Get the user's IP address and user-agent info
$userIP = getUserIp();
$userAgent = $_SERVER['HTTP_USER_AGENT'];
$authorizedCountries = $env["AUTHORIZED_COUNTRIES"] != null ? explode(',', $env["AUTHORIZED_COUNTRIES"]) : null;
$unauthorizedCountries = $env["UNAUTHORIZED_COUNTRIES"] != null ? explode(',', $env["UNAUTHORIZED_COUNTRIES"]) : null;

// Path to the text file containing IP addresses and ranges
$file = 'ip_addresses.txt';

// Read the IP addresses and ranges from the text file
$lines = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
$ipGeolocationData = getGeolocationInfoForIp($userIP);

if (in_array(strtolower($ipGeolocationData->country), $unauthorizedCountries)) {
    logUserInformation($userIP, $userAgent, $ipGeolocationData, false, 'Unauthorized country');
    header('Location: '. $env["REDIRECT_WEBSITE"] .'');
    exit();
}

// Check if the user's IP address matches any entry in the list
foreach ($lines as $line) {
    // Check if the line contains a single IP address
    if (filter_var($line, FILTER_VALIDATE_IP)) {
        if ($userIP === $line) {
            // Log user information in the database
            logUserInformation($userIP, $userAgent, $ipGeolocationData, false, 'Unauthorized IP address');

            // Redirect to website B
            header('Location: '. $env["REDIRECT_WEBSITE"] .'');
            exit();
        }
    } else {
        // Line contains an IP address range
        list($cidrIp, $cidrMask) = explode('/', $line);
        $rangeStart = (ip2long($cidrIp)) & ((-1 << (32 - $cidrMask)));
        $rangeEnd = (ip2long($cidrIp)) | ((1 << (32 - $cidrMask)) - 1);

        if (ip2long($userIP) >= $rangeStart && ip2long($userIP) <= $rangeEnd) {
            // Log user information in the database
            logUserInformation($userIP, $userAgent, $ipGeolocationData, false, 'Unauthorized IP subnet');

            // Redirect to website B
            header('Location: '. $env["REDIRECT_WEBSITE"] .'');
            exit();
        }
    }
}

// Redirect to website A
logUserInformation($userIP, $userAgent, $ipGeolocationData, true, null);
header('Location: '. $env["OFFICIAL_WEBSITE"] .'');
exit();

/**
 * Log user information in the database.
 *
 * @param string $ipAddress  The user's IP address.
 * @param string $userAgent  The user's user-agent information.
 */
function logUserInformation($ipAddress, $userAgent, $ipGeolocationData, $isAllowed, $redirectionReason)
{
    global $env;
    // Database connection settings
    $dbHost = $env["DATABASE_LOGIN_URL"];
    $dbName = $env["DATABASE_NAME"];
    $dbUser = $env["DATABASE_LOGIN"];
    $dbPass = $env["DATABASE_PASSWORD"];

    // Create a new PDO instance for the database connection
    $db = new PDO("mysql:host=$dbHost;dbname=$dbName", $dbUser, $dbPass);

    
    // Prepare the SQL statement to insert the user information
    $stmt = $db->prepare('INSERT INTO '. $env["DATABASE_TABLE_NAME"] .' (ip_address, city, region, country, location, isp, postal_code, timezone, is_allowed, redirection_reason) VALUES (:ip, :city, :region, :country, :location, :isp, :postal_code, :timezone, :is_allowed, :redirection_reason)');

    // Bind the values to the named parameters
    $stmt->bindValue(':ip', $ipAddress);
    $stmt->bindValue(':city', $ipGeolocationData->city);
    $stmt->bindValue(':region', $ipGeolocationData->region);
    $stmt->bindValue(':country', $ipGeolocationData->country);
    $stmt->bindValue(':location', $ipGeolocationData->loc);
    $stmt->bindValue(':isp', $ipGeolocationData->org);
    $stmt->bindValue(':postal_code', $ipGeolocationData->postal);
    $stmt->bindValue(':timezone', $ipGeolocationData->timezone);
    $stmt->bindValue(':is_allowed', $isAllowed ? 1 : 0);
    $stmt->bindValue(':redirection_reason', $redirectionReason);


    // Execute the SQL statement
    $stmt->execute();
    
    
}

function getGeolocationInfoForIp($userIp)
{
    $endpointWithParams = 'https://ipinfo.io/' . $userIp . '?token=1c3f802d799a38'; 
	$jsonResults = file_get_contents($endpointWithParams);
    return json_decode($jsonResults);

}
function getUserIp()
{
	global $_SERVER;
	if (!empty($_SERVER['HTTP_CLIENT_IP'])) {   //check ip from share internet
		$ip = $_SERVER['HTTP_CLIENT_IP'];
	} elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {   // to check ip is pass from proxy 
		$ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
	} else {
		$ip = $_SERVER['REMOTE_ADDR'];
	}
	return $ip;
}


