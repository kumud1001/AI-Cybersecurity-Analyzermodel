from app.network.packet_capture import start_capture


def monitor():

    print("Traffic Monitor Started")

    start_capture()


if __name__ == "__main__":

    monitor()