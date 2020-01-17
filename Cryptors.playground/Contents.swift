// Created by Vinay Hosamane K N
// vinayhosamane07@gmail.com
import CommonCrypto
import Foundation

//Encryption, Decryptiona and Derive Encryption Key methods.
protocol SecurityProvidable {
    ///  Generates random sequence of bytes for requested length.
    /// - Parameters:
    ///     - length: length of the random bytes to generate.
    /// - Returns: random sequence of bytes as optional 'Data' type.
    @discardableResult
    func encrypt(data value: Data, with key: Data) -> EncryptionResult
    
    ///  Abstracted Decrypt message convenience method.
    /// - Parameters:
    ///     - length: length of the random bytes to generate.
    /// - Returns: random sequence of bytes as optional 'Data' type.
    @discardableResult
    func decrypt(data value: Data, with key: Data) -> EncryptionResult
}

protocol RandomBytesGeneratable {
    ///  Generates random sequence of bytes for requested length.
    /// - Parameters:
    ///     - length: length of the random bytes to generate.
    /// - Returns: random sequence of bytes as optional 'Data' type.
    func generateRandomBytes(of length: Int32) -> Data?
    
    ///  Derives a secret key from password.
    /// - Parameters:
    ///     - password: app password set by user
    ///     - length: length of the derived secret key.
    /// - Returns: derived secret key as 'Data' type.
    func derivePBEncryptionKey(for password: String, ofLength length: Int) -> Data?
}

enum EncryptionResult {
    
    case failure(error: Int32)
    case success(value: Data)
    
    //Result
    func result() -> Data? {
        switch self {
        case .success(let result):
            return result
        case .failure(let error):
            print(ErrorMessageMapper.convertCryptoExceptionToReadableMessage(error: error))
            return nil
        }
    }
    
}

enum DataValidationError {
    
    case errorGeneratingSalt
    case errorGeneratingRandomBytes
    case invalidData
    
}

struct SecurityConstants {
    
    //Lenght of the block size = 128
    static let blockSize: Int = kCCBlockSizeAES128
    //Number of iterations = 1000
    static let iterationsCount = 1000
    //Salt size in byes
    static let saltSize: Int32 = CC_SHA256_DIGEST_LENGTH
    //Length of the encryption key = 256 bytes
    static let secretKeyLength: Int = kCCKeySizeAES256
    
    //Common Crypto exception message constants
    static let bufferError = "CommonCrypto: Buffer is too small."
    static let bufferOverflow = "CommonCypto: Buffer overflow."
    static let callSequenceError = "CommonCypto: Call sequence error."
    static let decodeError = "CommonCypto: Decode error."
    static let invalidKey = "CommonCypto: Invalid key."
    static let keySizeError = "CommonCypto: Key size error."
    static let memoryFailure = "CommonCypto: Memory failure."
    static let paramError = "CommonCypto: Parameter Error."
    static let unspecifiedError = "CommonCypto: Unspecified error."
    static let unknownError = "CommonCrypto: Unknown error."
    
}


@objc
final class Cryptor: NSObject, SecurityProvidable, RandomBytesGeneratable {
    
    @objc static let sharedInstance = Cryptor()
    
    // MARK: Encryption and Decryption convenience Methods.
    ///  Generates random sequence of bytes for requested length.
    /// - Parameters:
    ///     - value: length of the random bytes to generate.
    ///     - key: encryption key
    /// - Returns: random sequence of bytes as optional 'Data' type.
    func encrypt(data value: Data, with key: Data) -> EncryptionResult {
        return cipheriseData(input: value, with: key, operation: CCOperation(kCCEncrypt))
    }
    
    ///  Abstracted Decrypt message convenience method.
    /// - Parameters:
    ///     - value: length of the random bytes to generate.
    ///     - key: encryption key
    /// - Returns: random sequence of bytes as optional 'Data' type.
    func decrypt(data value: Data, with key: Data) -> EncryptionResult {
        return cipheriseData(input: value, with: key, operation: CCOperation(kCCDecrypt))
    }
    
    // MARK: CommonCrypto CCCrypt Implementation.
    ///  Applies Cryptographic operation like Encrypt and Decrypt on message passed.
    /// - Parameters:
    ///     - value: message to be secured.
    ///     - operation: It can be either KCCEncrypt or KCCDecrypt.
    /// - Returns: enum of type EncryptionResult, which has success and failure cases.
    private func cipheriseData(input value: Data, with key: Data, operation: CCOperation) -> EncryptionResult {
        //message and key
        var localKey = key
        let localkeyLength = Int(localKey.count)
        var localMessage = value
        let localMessageLength = Int(localMessage.count)
        //output
        let outputData = Data(count: (localMessage.count + SecurityConstants.blockSize))
        var localOutput = outputData
        let localOutputDataLength = Int(localOutput.count)
        //output length
        var outputLength: size_t = 0
        
        //encyrption
        let status = localKey.withUnsafeMutableBytes { keyBytes in
            localMessage.withUnsafeMutableBytes { messageBytes in
                localOutput.withUnsafeMutableBytes { mutableOutput in
                    CCCrypt( operation,
                             CCAlgorithm(kCCAlgorithmAES128),
                             CCOptions(kCCOptionPKCS7Padding),
                             keyBytes.baseAddress,
                             localkeyLength,
                             nil,
                             messageBytes.baseAddress,
                             localMessageLength,
                             mutableOutput.baseAddress,
                             localOutputDataLength,
                             &outputLength)
                }
            }
        }
        guard status == Int32(kCCSuccess) else {
            print("Error: Can not encrypt data")
            return EncryptionResult.failure(error: status)
        }
        
        localOutput.count = outputLength
        return EncryptionResult.success(value: localOutput)
    }
    
    // MARK: Encryption Key Generators.
    ///  Generates random sequence of bytes for requested length.
    /// - Parameters:
    ///     - length: length of the random bytes to generate.
    /// - Returns: random sequence of bytes as optional 'Data' type.
    func generateRandomBytes(of length: Int32) -> Data? {
        var randomBytes = Data(count: Int(length))
        
        let result = randomBytes.withUnsafeMutableBytes { mutableBytes in
            SecRandomCopyBytes(kSecRandomDefault, Int(length), (mutableBytes.bindMemory(to: Int32.self).baseAddress)!)
        }
        
        guard result == errSecSuccess else {
            print("Error: Not able to generate random bytes sequence")
            return nil
        }
        return randomBytes
    }
    
    ///  Derives a secret key from password.
    /// - Parameters:
    ///     - password: app password set by user
    ///     - length: length of the derived secret key.
    /// - Returns: derived secret key as 'Data' type.
    func derivePBEncryptionKey(for password: String, ofLength length: Int) -> Data? {
        var derivedKey = Data(count: length)
        //Created since we can not access derived key while modifications are in progress.
        let tempDerivedKey = derivedKey
        let passwordData = password.data(using: .utf8)
        guard var saltData = generateRandomBytes(of: SecurityConstants.saltSize) else {
            print("Error: Invalid Salt")
            return nil
        }
        
        let result = derivedKey.withUnsafeMutableBytes { derivedKeyBytes in
            saltData.withUnsafeBytes { saltBytes in
                passwordData?.withUnsafeBytes { passwordBytes in
                    CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                                         passwordBytes.bindMemory(to: Int8.self).baseAddress,
                                         password.count,
                                         saltBytes.bindMemory(to: UInt8.self).baseAddress,
                                         saltData.count,
                                         CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                                         UInt32(SecurityConstants.iterationsCount),
                                         derivedKeyBytes.bindMemory(to: UInt8.self).baseAddress,
                                         tempDerivedKey.count)
                }
            }
        }
        
        guard result == 0 else {
            print("Error: Could not derive encryption key from password")
            return nil
        }
        
        //We are not supposed to use derived key directky while commoncrypto is using it. So copying it to local constant.
        let finalDerivedKey = derivedKey
        return finalDerivedKey
    }
    
}

class ErrorMessageMapper {
    
    //Coomon Crypto errors from CommonCryptoError.h
    /*
     enum {
     kCCSuccess          = 0,
     kCCParamError       = -4300,
     kCCBufferTooSmall   = -4301,
     kCCMemoryFailure    = -4302,
     kCCAlignmentError   = -4303,
     kCCDecodeError      = -4304,
     kCCUnimplemented    = -4305,
     kCCOverflow         = -4306,
     kCCRNGFailure       = -4307,
     kCCUnspecifiedError = -4308,
     kCCCallSequenceError= -4309,
     kCCKeySizeError     = -4310,
     kCCInvalidKey       = -4311,
     }; */
    static func convertCryptoExceptionToReadableMessage(error: Int32) -> String {
        switch error {
        case -4300:
            return SecurityConstants.paramError
        case -4301:
            return SecurityConstants.bufferError
        case -4302:
            return SecurityConstants.memoryFailure
        case -4304:
            return SecurityConstants.decodeError
        case -4306:
            return SecurityConstants.bufferOverflow
        case -4308:
            return SecurityConstants.unspecifiedError
        case -4309:
            return SecurityConstants.callSequenceError
        case -4310:
            return SecurityConstants.keySizeError
        case -4311:
            return SecurityConstants.invalidKey
        default:
            return SecurityConstants.unknownError
        }
    }
    
}

// Unifrom way of converting data to string and vice versa, Base 64 makes sure to use 64 character set. Which assures the data won't get corrupted
extension Data {
    
    ///Converts Data type into base 64 encoded String.
    func toString() -> String {
        return self.base64EncodedString()
    }
    
}

extension String {
    
    ///Converts String into base 64 decoded Data.
    func toData() -> Data? {
        guard let data = Data(base64Encoded: self, options: .ignoreUnknownCharacters) else {
            return nil
        }
        return data
    }
    
}

//SetAppPassword flow
func test() {
    guard let newKey = Cryptor.sharedInstance.derivePBEncryptionKey(for: "password",
                                                                    ofLength: SecurityConstants.secretKeyLength),
        let newSalt = Cryptor.sharedInstance.generateRandomBytes(of: Int32(SecurityConstants.saltSize)) else {
            return
    }
    print("Key is: \(newKey.toString())")
    print("Salt is: \(newSalt.toString())")
    
    guard let encryptedSalt = Cryptor.sharedInstance.encrypt(data: newSalt, with: newKey).result() else {
        print("Error in encryption")
        return
    }
    print("Encrypted data: \(encryptedSalt.toString())")
}

test()
