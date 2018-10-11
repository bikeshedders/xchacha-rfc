<?php
declare(strict_types=1);

use ParagonIE_Sodium_Compat as Sodium;

require 'vendor/autoload.php';

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
 * Test vector #1
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

if (tv1() && tv2()) {
    echo 'All tests passed!', PHP_EOL;
}
