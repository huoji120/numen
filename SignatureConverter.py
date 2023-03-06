# CSGO IDA Signature Converter
#
# written by cragson

from time import sleep

def convertSig( sig ):
    return ''.join( sig.strip().replace( ' ', '' ) )

def generateByteSignature( sig ):
    Signature = convertSig( sig )
    ByteSignature = []

    for element in range( 0, len( Signature ), 2 ):
        if( str( Signature[ element ] + Signature[ element + 1 ] ) == "??" ):
            ByteSignature.append( r'\xCC' ) # wildcard byte 
            
            continue
        
        ByteSignature.append( r'\x' + str( Signature[ element ] ) + str( Signature[ element + 1 ] ) )

    return ''.join( ByteSignature )
    
def generateMask( sig ):
    Signature = convertSig( sig )
    ByteSignature = []

    for element in range( 0, len( Signature ), 2 ):
        if( str( Signature[ element ] + Signature[ element + 1 ] ) == "??" ):
            ByteSignature.append( '?' )
            
            continue
        else:
            ByteSignature.append( 'x' )
        
    return ''.join( ByteSignature )

def main():
    while( True ):
        signature = input( " Please enter your signature. \n>> " )
        print( "\n Byte Signature : " + generateByteSignature( signature ) )
        print( " Mask : " + generateMask( signature ) + "\n")
        sleep(0.1)
    
if __name__ == '__main__':
    main()
