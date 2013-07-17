/*  rtmpnb - Diffie-Hellmann Key Exchange
 *  Copyright (C) 2009 Andrej Stepanchuk
 *
 *  This file is part of rtmpnb.
 *
 *  rtmpnb is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as
 *  published by the Free Software Foundation; either version 2.1,
 *  or (at your option) any later version.
 *
 *  rtmpnb is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with rtmpnb see the file COPYING.  If not, write to
 *  the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 *  Boston, MA  02110-1301, USA.
 *  http://www.gnu.org/copyleft/lgpl.html
 */

/* from RFC 3526, see http://www.ietf.org/rfc/rfc3526.txt */

/* 2^768 - 2 ^704 - 1 + 2^64 * { [2^638 pi] + 149686 } */
#define P768 \
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" \
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" \
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" \
	"E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF"

/* 2^1024 - 2^960 - 1 + 2^64 * { [2^894 pi] + 129093 } */
#define P1024 \
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" \
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" \
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" \
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" \
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381" \
	"FFFFFFFFFFFFFFFF"

/* Group morder largest prime factor: */
#define Q1024 \
	"7FFFFFFFFFFFFFFFE487ED5110B4611A62633145C06E0E68" \
        "948127044533E63A0105DF531D89CD9128A5043CC71A026E" \
        "F7CA8CD9E69D218D98158536F92F8A1BA7F09AB6B6A8E122" \
        "F242DABB312F3F637A262174D31BF6B585FFAE5B7A035BF6" \
        "F71C35FDAD44CFD2D74F9208BE258FF324943328F67329C0" \
        "FFFFFFFFFFFFFFFF"

/* 2^1536 - 2^1472 - 1 + 2^64 * { [2^1406 pi] + 741804 } */
#define P1536 \
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" \
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" \
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" \
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" \
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" \
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" \
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D" \
        "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF"

/* 2^2048 - 2^1984 - 1 + 2^64 * { [2^1918 pi] + 124476 } */
#define P2048 \
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" \
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" \
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" \
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" \
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" \
	"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" \
	"83655D23DCA3AD961C62F356208552BB9ED529077096966D" \
	"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" \
	"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" \
	"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" \
	"15728E5A8AACAA68FFFFFFFFFFFFFFFF"

/* 2^3072 - 2^3008 - 1 + 2^64 * { [2^2942 pi] + 1690314 } */
#define P3072 \
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" \
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" \
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" \
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" \
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" \
	"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" \
	"83655D23DCA3AD961C62F356208552BB9ED529077096966D" \
	"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" \
	"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" \
	"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" \
	"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" \
	"ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" \
	"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" \
	"F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" \
	"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" \
	"43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"

/* 2^4096 - 2^4032 - 1 + 2^64 * { [2^3966 pi] + 240904 } */
#define P4096 \
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" \
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" \
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" \
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" \
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" \
	"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" \
	"83655D23DCA3AD961C62F356208552BB9ED529077096966D" \
	"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" \
	"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" \
	"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" \
	"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" \
	"ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" \
	"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" \
	"F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" \
	"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" \
	"43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7" \
	"88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA" \
	"2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6" \
	"287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED" \
	"1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9" \
	"93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199" \
	"FFFFFFFFFFFFFFFF"

/* 2^6144 - 2^6080 - 1 + 2^64 * { [2^6014 pi] + 929484 } */
#define P6144 \
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" \
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" \
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" \
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" \
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" \
	"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" \
	"83655D23DCA3AD961C62F356208552BB9ED529077096966D" \
	"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" \
	"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" \
	"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" \
	"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" \
	"ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" \
	"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" \
	"F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" \
	"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" \
	"43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7" \
	"88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA" \
	"2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6" \
	"287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED" \
	"1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9" \
	"93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492" \
	"36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BD" \
	"F8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831" \
	"179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1B" \
	"DB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF" \
	"5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6" \
	"D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F3" \
	"23A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA" \
	"CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE328" \
	"06A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55C" \
	"DA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE" \
	"12BF2D5B0B7474D6E694F91E6DCC4024FFFFFFFFFFFFFFFF"

/* 2^8192 - 2^8128 - 1 + 2^64 * { [2^8062 pi] + 4743158 } */
#define P8192 \
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" \
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" \
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" \
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" \
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" \
	"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" \
	"83655D23DCA3AD961C62F356208552BB9ED529077096966D" \
	"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" \
	"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" \
	"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" \
	"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" \
	"ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" \
	"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" \
	"F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" \
	"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" \
	"43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7" \
	"88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA" \
	"2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6" \
	"287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED" \
	"1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9" \
	"93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492" \
	"36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BD" \
	"F8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831" \
	"179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1B" \
	"DB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF" \
	"5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6" \
	"D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F3" \
	"23A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA" \
	"CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE328" \
	"06A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55C" \
	"DA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE" \
	"12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E4" \
	"38777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300" \
	"741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F568" \
	"3423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD9" \
	"22222E04A4037C0713EB57A81A23F0C73473FC646CEA306B" \
	"4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A" \
	"062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A36" \
	"4597E899A0255DC164F31CC50846851DF9AB48195DED7EA1" \
	"B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F92" \
	"4009438B481C6CD7889A002ED5EE382BC9190DA6FC026E47" \
	"9558E4475677E9AA9E3050E2765694DFC81F56E880B96E71" \
	"60C980DD98EDD3DFFFFFFFFFFFFFFFFF"

