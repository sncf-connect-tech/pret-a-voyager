export class EncryptionService {

    /**
     * Permet d'encrypter un message
     * @param msg message à encrypté
     * @param serverPublicKey clé public du server
     * @returns Message encrypté
     */
    public async encryptMessage(msg: string): Promise<IEncryptedPassData> {
        const clientKeyPair: CryptoKeyPair = await this.generateKey();
        const serverPublicKey = await this.importServerPublicKey();
        const signatureKey = await this.getSignatureKey(serverPublicKey, clientKeyPair);
        const signature = await this.getSignature(signatureKey);
        const sharedSecret = await this.getSharedSecret(signature);

        let enc = new TextEncoder();
        const iv = Array.from(Array(16), () => Math.floor(Math.random() * 36).toString(36)).join('');
        const ivByteArray = new Uint8Array(Buffer.from(iv, 'base64'));

        const ciphertext = await crypto.subtle.encrypt(
            {
              name: "AES-GCM",
              iv: ivByteArray
            },
            sharedSecret,
            enc.encode(msg)
        );

        return {
            iv,
            ciphertext: Buffer.from(ciphertext).toString('base64'),
            key: await this.exportSharedKey(clientKeyPair.publicKey as CryptoKey)
        };
    }

    /**
     * Permet de récupérer le shared secret
     */
    private async getSignatureKey(serverPublicKey: CryptoKey, clientKeyPair: CryptoKeyPair) {
        return await crypto.subtle.deriveKey(
            {
                name: 'ECDH',
                public: serverPublicKey
            },
            clientKeyPair.privateKey as CryptoKey,
            {
                name: 'HMAC',
                hash: 'SHA-256'
            },
            true,
            ['sign']
        );
    }

    /**
     * Permet de générer la signature
     * @param sharedSecret Clé partagé
     * @returns Signature sous forme d'arraybuffer
     */
    private async getSignature(sharedSecret: CryptoKey): Promise<ArrayBuffer> {
        return await crypto.subtle.sign(
            "HMAC",
            sharedSecret,
            new TextEncoder().encode('conversion')
        );
    }

    /**
     * Permet de récupérer la shared key
     * @returns CryptoKey
     */
    private async getSharedSecret(signature: ArrayBuffer): Promise<CryptoKey> {
        return await crypto.subtle.importKey(
            'raw',
            signature,
            {
                name: 'AES-GCM'
            },
            true,
            ['encrypt']
        );
    }

    /**
     * Permet d'exporter la share key
     * @param key CryptoKey à exporter
     * @returns Chaine de caractère base64
     */
    private async exportSharedKey(key: CryptoKey): Promise<string> {
        const result = await crypto.subtle.exportKey(
            'spki',
            key
        );
        return Buffer.from(result).toString('base64');
    }

    /**
     * Permet de générer une nouvelle bi clé
     */
    private async generateKey(): Promise<CryptoKeyPair> {
        return await crypto.subtle.generateKey(
            {
                name: 'ECDH',
                namedCurve: 'P-256'
            },
            true,
            ['deriveKey']
        );
    }

    /**
     * Permet d'importer la clé public du server
     * @returns Clé public du serveur
     */
    private importServerPublicKey(): Promise<CryptoKey> {
        return crypto.subtle.importKey(
            'spki',
            this.toArrayBuffer(Buffer.from(environment.tac.publicKey, 'base64')),
            {
                name: 'ECDH',
                namedCurve: 'P-256'
            },
            true,
            []
        );
    }

    /**
     * Permet de convertir un buffer en arraybuffer
     * @param buf buffer
     * @returns arraybuffer
     */
    private toArrayBuffer(buf: Buffer) {
        const ab = new ArrayBuffer(buf.length);
        const view = new Uint8Array(ab);
        for (let i = 0; i < buf.length; ++i) {
            view[i] = buf[i];
        }
        return ab;
    }
}
