def extract(packet):

    return {

        "length":len(packet),

        "protocol":packet.summary()

    }