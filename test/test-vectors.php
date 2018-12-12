<?php
declare(strict_types=1);

use ParagonIE_Sodium_Compat as Sodium;

require 'vendor/autoload.php';

class HChaChaDumper extends ParagonIE_Sodium_Core_HChaCha20
{
    /**
     * @param string $in
     * @param string $key
     * @param string|null $c
     * @return string
     * @throws TypeError
     */
    public static function hChaCha20($in = '', $key = '', $c = null)
    {
        $ctx = array();

        if ($c === null) {
            $ctx[0] = 0x61707865;
            $ctx[1] = 0x3320646e;
            $ctx[2] = 0x79622d32;
            $ctx[3] = 0x6b206574;
        } else {
            $ctx[0] = self::load_4(self::substr($c,  0, 4));
            $ctx[1] = self::load_4(self::substr($c,  4, 4));
            $ctx[2] = self::load_4(self::substr($c,  8, 4));
            $ctx[3] = self::load_4(self::substr($c, 12, 4));
        }
        $ctx[4]  = self::load_4(self::substr($key,  0, 4));
        $ctx[5]  = self::load_4(self::substr($key,  4, 4));
        $ctx[6]  = self::load_4(self::substr($key,  8, 4));
        $ctx[7]  = self::load_4(self::substr($key, 12, 4));
        $ctx[8]  = self::load_4(self::substr($key, 16, 4));
        $ctx[9]  = self::load_4(self::substr($key, 20, 4));
        $ctx[10] = self::load_4(self::substr($key, 24, 4));
        $ctx[11] = self::load_4(self::substr($key, 28, 4));
        $ctx[12] = self::load_4(self::substr($in,   0, 4));
        $ctx[13] = self::load_4(self::substr($in,   4, 4));
        $ctx[14] = self::load_4(self::substr($in,   8, 4));
        $ctx[15] = self::load_4(self::substr($in,  12, 4));
        return static::hChaCha20Bytes($ctx);
    }

    /**
     * @param array $ctx
     * @return string
     * @throws TypeError
     */
    protected static function hChaCha20Bytes(array $ctx)
    {
        $x0 = (int)$ctx[0];
        $x1 = (int)$ctx[1];
        $x2 = (int)$ctx[2];
        $x3 = (int)$ctx[3];
        $x4 = (int)$ctx[4];
        $x5 = (int)$ctx[5];
        $x6 = (int)$ctx[6];
        $x7 = (int)$ctx[7];
        $x8 = (int)$ctx[8];
        $x9 = (int)$ctx[9];
        $x10 = (int)$ctx[10];
        $x11 = (int)$ctx[11];
        $x12 = (int)$ctx[12];
        $x13 = (int)$ctx[13];
        $x14 = (int)$ctx[14];
        $x15 = (int)$ctx[15];

        for ($i = 0; $i < 10; ++$i) {
            # QUARTERROUND( x0,  x4,  x8,  x12)
            list($x0, $x4, $x8, $x12) = self::quarterRound($x0, $x4, $x8, $x12);

            # QUARTERROUND( x1,  x5,  x9,  x13)
            list($x1, $x5, $x9, $x13) = self::quarterRound($x1, $x5, $x9, $x13);

            # QUARTERROUND( x2,  x6,  x10,  x14)
            list($x2, $x6, $x10, $x14) = self::quarterRound($x2, $x6, $x10, $x14);

            # QUARTERROUND( x3,  x7,  x11,  x15)
            list($x3, $x7, $x11, $x15) = self::quarterRound($x3, $x7, $x11, $x15);

            # QUARTERROUND( x0,  x5,  x10,  x15)
            list($x0, $x5, $x10, $x15) = self::quarterRound($x0, $x5, $x10, $x15);

            # QUARTERROUND( x1,  x6,  x11,  x12)
            list($x1, $x6, $x11, $x12) = self::quarterRound($x1, $x6, $x11, $x12);

            # QUARTERROUND( x2,  x7,  x8,  x13)
            list($x2, $x7, $x8, $x13) = self::quarterRound($x2, $x7, $x8, $x13);

            # QUARTERROUND( x3,  x4,  x9,  x14)
            list($x3, $x4, $x9, $x14) = self::quarterRound($x3, $x4, $x9, $x14);
        }

        return self::store32_be((int)($x0 & 0xffffffff)) .
            self::store32_be((int)($x1 & 0xffffffff)) .
            self::store32_be((int)($x2 & 0xffffffff)) .
            self::store32_be((int)($x3 & 0xffffffff)) .
            self::store32_be((int)($x4 & 0xffffffff)) .
            self::store32_be((int)($x5 & 0xffffffff)) .
            self::store32_be((int)($x6 & 0xffffffff)) .
            self::store32_be((int)($x7 & 0xffffffff)) .
            self::store32_be((int)($x8 & 0xffffffff)) .
            self::store32_be((int)($x9 & 0xffffffff)) .
            self::store32_be((int)($x10 & 0xffffffff)) .
            self::store32_be((int)($x11 & 0xffffffff)) .
            self::store32_be((int)($x12 & 0xffffffff)) .
            self::store32_be((int)($x13 & 0xffffffff)) .
            self::store32_be((int)($x14 & 0xffffffff)) .
            self::store32_be((int)($x15 & 0xffffffff));
    }
    /**
     * Store a 32-bit integer into a string, treating it as little-endian.
     *
     * @internal You should not use this directly from another application
     *
     * @param int $int
     * @return string
     * @throws TypeError
     */
    public static function store32_be($int)
    {
        /* Type checks: */
        if (!is_int($int)) {
            if (is_numeric($int)) {
                $int = (int) $int;
            } else {
                throw new TypeError('Argument 1 must be an integer, ' . gettype($int) . ' given.');
            }
        }
        return self::hex2bin(str_pad(dechex($int), 8, '0', STR_PAD_LEFT));
    }
}

/**
 * Test vector #1
 *
 * @return bool
 * @throws SodiumException
 */
function tv1(): bool
{
    $plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    $key = Sodium::hex2bin("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    $aad = Sodium::hex2bin("50515253c0c1c2c3c4c5c6c7");
    $iv = Sodium::hex2bin("404142434445464748494a4b4c4d4e4f5051525354555657");
    $tag = Sodium::hex2bin("c0875924c1c7987947deafd8780acf49");
    $expected = Sodium::hex2bin("bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e");
    $expected .= $tag;

    $ciphertext = Sodium::crypto_aead_xchacha20poly1305_ietf_encrypt(
        $plaintext,
        $aad,
        $iv,
        $key
    );

    if (!hash_equals($expected, $ciphertext)) {
        echo "Incorrect test vector!\n";
        echo '- ' . Sodium::bin2hex($expected) . PHP_EOL;
        echo '- ' . Sodium::bin2hex($ciphertext) . PHP_EOL;
        return false;
    }
    return true;
}
/**
 * Test vector #2
 *
 * @return bool
 * @throws SodiumException
 */
function tv2(): bool
{
    $plaintext = "The dhole (pronounced \"dole\") is also known as the Asiatic wild dog, red dog, and whistling dog. It is about the size of a German shepherd but looks more like a long-legged fox. This highly elusive and skilled jumper is classified with wolves, coyotes, jackals, and foxes in the taxonomic family Canidae.";
    $key = Sodium::hex2bin("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    $iv = Sodium::hex2bin("404142434445464748494a4b4c4d4e4f5051525354555658");
    $expected = Sodium::hex2bin("4559abba4e48c16102e8bb2c05e6947f50a786de162f9b0b7e592a9b53d0d4e98d8d6410d540a1a6375b26d80dace4fab52384c731acbf16a5923c0c48d3575d4d0d2c673b666faa731061277701093a6bf7a158a8864292a41c48e3a9b4c0daece0f8d98d0d7e05b37a307bbb66333164ec9e1b24ea0d6c3ffddcec4f68e7443056193a03c810e11344ca06d8ed8a2bfb1e8d48cfa6bc0eb4e2464b748142407c9f431aee769960e15ba8b96890466ef2457599852385c661f752ce20f9da0c09ab6b19df74e76a95967446f8d0fd415e7bee2a12a114c20eb5292ae7a349ae577820d5520a1f3fb62a17ce6a7e68fa7c79111d8860920bc048ef43fe84486ccb87c25f0ae045f0cce1e7989a9aa220a28bdd4827e751a24a6d5c62d790a66393b93111c1a55dd7421a10184974c7c5");
    $ciphertext = ParagonIE_Sodium_Core_XChaCha20::streamXorIc($plaintext, $iv, $key);

    if (!hash_equals($expected, $ciphertext)) {
        echo "Incorrect test vector!\n";
        echo '- ' . Sodium::bin2hex($expected) . PHP_EOL;
        echo '- ' . Sodium::bin2hex($ciphertext) . PHP_EOL;
        return false;
    }
    return true;
}

function hchacha20(): bool
{
    $key = Sodium::hex2bin("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    $nonce = Sodium::hex2bin("000000090000004a0000000031415927");
    $expected = Sodium::hex2bin("423b4182fe7bb22750420ed3737d878a0aa764487954cdf3846acd377b3c58ad77e3558383e77c12e0076a2dbc6cd0e5d5e4f9a053a8748a13c42ec1dcecd326");
    $fullState = HChaChaDumper::hChaCha20($nonce, $key);

    if (!hash_equals($expected, $fullState)) {
        echo "Incorrect test vector!\n";
        echo '- ' . Sodium::bin2hex($expected) . PHP_EOL;
        echo '- ' . Sodium::bin2hex($fullState) . PHP_EOL;
        return false;
    }
    return true;
}

if (tv1() && tv2() && hchacha20()) {
    echo 'All tests passed!', PHP_EOL;
}
