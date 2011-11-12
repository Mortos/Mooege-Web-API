<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * functions.php
 */





// convert ascii string to Hex
function ascii_to_hex($ascii_string)
{
    foreach (str_split($ascii_string) as $chr)
    {
        $hex_string .= dechex(ord($chr));
    }

    return $hex_string;
}





// regex for check email sintax
function emailCheck($email)
{
    if (!ereg("^[^@]{1,64}@[^@]{1,255}$", $email))
    {
        return false;
    }

    $email_array = explode("@", $email);
    $local_array = explode(".", $email_array[0]);
    for ($i = 0; $i < sizeof($local_array); $i++)
    {
        if (!ereg("^(([A-Za-z0-9!#$%&'*+/=?^_`{|}~-][A-Za-z0-9!#$%&'*+/=?^_`{|}~\.-]{0,63})|(\"[^(\\|\")]{0,62}\"))$", $local_array[$i]))
        {
            return false;
        }
    }

    // Check if domain is IP. If not,
    // it should be valid domain name
    if (!ereg("^\[?[0-9\.]+\]?$", $email_array[1]))
    {
        $domain_array = explode(".", $email_array[1]);
        if (sizeof($domain_array) < 2)
        {
            return false; // Not enough parts to domain
        }

        for ($i = 0; $i < sizeof($domain_array); $i++)
        {
            if (!ereg("^(([A-Za-z0-9][A-Za-z0-9-]{0,61}[A-Za-z0-9])|([A-Za-z0-9]+))$", $domain_array[$i]))
            {
                return false;
            }
        }
    }

    return true;
}





/**
 * Function getRandomByte, this is very bad random functions because openssl_random_pseudo_bytes()
 * require ssl fullinstalled and configured with php/httpdeamon and i think that not all person is
 * able to install it.
 */
function getRandomByte($email)
{

    $time = strtotime("now");
    $characters = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    $randstring = '';
    for ($i = 0; $i < 18; $i++)
    {
        $randchar = $characters[rand(0, strlen($characters))];
    }

    $randstring = hash(sha256,$randchar.$time);

    return hash(sha256,$randchar.$time,false);
}





function hex2bin($hex_string)
{
    $bin_string = '';

    for ($i = 0; $i < strlen($hex_string); $i += 2)
    {
        $bin_string .= chr(hexdec(substr($hex_string, $i, 2)));
    }

    return $bin_string;
}





function bintohex($bin_string)
{
    $i = 0;
    $hex_string = '';

    do {
        $hex_string .= dechex(ord($bin_string{$i}));
        $i++;
    } while ($i < strlen($bin_string));

    return $hex_string;
}





function encodeBytes($input)
{
    // The following is code from the PHP Password Hashing Framework
    $itoa64 = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

    $output = '';
    $i = 0;
    do {
        $c1 = ord($input[$i++]);
        $output .= $itoa64[$c1 >> 2];
        $c1 = ($c1 & 0x03) << 4;
        if ($i >= 16) {
            $output .= $itoa64[$c1];
            break;
        }

        $c2 = ord($input[$i++]);
        $c1 |= $c2 >> 4;
        $output .= $itoa64[$c1];
        $c1 = ($c2 & 0x0f) << 2;

        $c2 = ord($input[$i++]);
        $c1 |= $c2 >> 6;
        $output .= $itoa64[$c1];
        $output .= $itoa64[$c2 & 0x3f];
        } while (1);

    return $output;
}





/* EOF */
?>