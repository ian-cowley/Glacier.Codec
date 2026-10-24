using System;
using System.IO;
using System.Security.Cryptography;
using Xunit;
using Glacier.Codec.Cryptography.ChaCha20Poly1305;
using Glacier.Codec.Hashing.Blake3;
using Glacier.Codec.Memory;

namespace Glacier.Codec.Tests.E2E.Tier4_RealWorldScenarios;

public class Tier4_ZeroCopyNetworkStreaming
{
    [Fact]
    public void Scenario_ZeroCopyNetworkStreaming_AuthenticatedTunnel()
    {
        // 1. Establish pre-shared session keys
        byte[] macKey = new byte[32];
        byte[] cipherKey = new byte[32];
        RandomNumberGenerator.Fill(macKey);
        RandomNumberGenerator.Fill(cipherKey);

        const int frameCount = 10;
        const int payloadSizePerFrame = 4096;

        using var memoryStream = new MemoryStream();

        // 2. Sender: Stream frames using 64-byte CachelineAlignedBuffer
        using (var sendBuffer = new CachelineAlignedBuffer(payloadSizePerFrame))
        {
            Assert.True(sendBuffer.IsAlignedTo64Bytes);

            Span<byte> macTag = stackalloc byte[32];
            Span<byte> nonce = stackalloc byte[12];
            Span<byte> polyTag = stackalloc byte[16];
            byte[] ciphertext = new byte[payloadSizePerFrame];

            for (ulong frameSeq = 0; frameSeq < frameCount; frameSeq++)
            {
                // Populate send buffer
                Span<byte> span = sendBuffer.Span;
                span.Fill((byte)(frameSeq & 0xFF));

                // Compute BLAKE3 MAC over frame body
                Blake3Hasher.HashKeyed(span, macKey, macTag);

                // Form 96-bit nonce from sequence
                System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(nonce.Slice(0, 8), frameSeq);

                // Encrypt payload via ChaCha20-Poly1305 AEAD with MAC tag as Associated Data
                ChaCha20Poly1305Cipher.Encrypt(cipherKey, nonce, span, ciphertext, polyTag, macTag);

                // Write packet: [Sequence (8B)] [PolyTag (16B)] [Blake3Tag (32B)] [Ciphertext (4096B)]
                memoryStream.Write(nonce.Slice(0, 8));
                memoryStream.Write(polyTag);
                memoryStream.Write(macTag);
                memoryStream.Write(ciphertext);
            }
        }

        // 3. Receiver: Decode and verify stream
        memoryStream.Position = 0;
        using var recvBuffer = new CachelineAlignedBuffer(payloadSizePerFrame);

        Span<byte> recvSeqBytes = stackalloc byte[8];
        Span<byte> recvPolyTag = stackalloc byte[16];
        Span<byte> recvMacTag = stackalloc byte[32];
        byte[] recvCiphertext = new byte[payloadSizePerFrame];
        Span<byte> recvNonce = stackalloc byte[12];
        Span<byte> verifyMac = stackalloc byte[32];

        for (ulong frameSeq = 0; frameSeq < frameCount; frameSeq++)
        {
            int readSeq = memoryStream.Read(recvSeqBytes);
            Assert.Equal(8, readSeq);
            ulong receivedSeq = System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(recvSeqBytes);
            Assert.Equal(frameSeq, receivedSeq);

            memoryStream.ReadExactly(recvPolyTag);
            memoryStream.ReadExactly(recvMacTag);
            memoryStream.ReadExactly(recvCiphertext);

            System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(recvNonce.Slice(0, 8), receivedSeq);

            // Decrypt & authenticate
            Span<byte> plaintext = recvBuffer.Span;
            bool authOk = ChaCha20Poly1305Cipher.Decrypt(cipherKey, recvNonce, recvCiphertext, recvPolyTag, plaintext, recvMacTag);
            Assert.True(authOk, $"AEAD tag authentication failed on frame {receivedSeq}");

            // Verify BLAKE3 MAC
            Blake3Hasher.HashKeyed(plaintext, macKey, verifyMac);
            Assert.True(CryptographicOperations.FixedTimeEquals(recvMacTag, verifyMac), "BLAKE3 MAC verification mismatch.");

            // Verify content
            Assert.Equal((byte)(frameSeq & 0xFF), plaintext[0]);
            Assert.Equal((byte)(frameSeq & 0xFF), plaintext[payloadSizePerFrame - 1]);
        }
    }
}
