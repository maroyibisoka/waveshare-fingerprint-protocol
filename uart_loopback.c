#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/time.h>

#define DEVICE      "/dev/ttyAMA0"
#define BAUD_RATE   19200
#define PACKET_SIZE 256


int uart_fd = -1;

unsigned long millis()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000UL) + (tv.tv_usec / 1000UL);
}


// New uart_init func for test
int uart_init(int baud) {
    // int fd = open(DEVICE, O_RDWR | O_NOCTTY); // blocking mode
    int fd = open(DEVICE, O_RDWR | O_NOCTTY | O_NDELAY); // no blocking mode


    if (fd == -1) {
        perror("Unable to open UART");
        exit(EXIT_FAILURE);
    }

    struct termios options;
    tcgetattr(fd, &options);

    cfmakeraw(&options);

    // Baud rate
    speed_t speed = baud;
    cfsetispeed(&options, speed);
    cfsetospeed(&options, speed);

    // 8N1 configuration
    options.c_cflag &= ~PARENB;   // no parity
    options.c_cflag &= ~CSTOPB;   // 1 stop bit
    options.c_cflag &= ~CSIZE;
    options.c_cflag |= CS8;       // 8 data bits

    // Enable receiver, ignore modem lines
    options.c_cflag |= (CLOCAL | CREAD);

    // No flow control
    options.c_cflag &= ~CRTSCTS;

    // Read behavior
    options.c_cc[VMIN] = 1;
    options.c_cc[VTIME] = 0;

    tcflush(fd, TCIFLUSH);
    tcsetattr(fd, TCSANOW, &options);

    return fd;
}

int main() {
    uart_fd = uart_init(B19200);

    uint8_t packet[PACKET_SIZE], response[PACKET_SIZE];
    for (int i = 0; i < PACKET_SIZE; i++)
    {
        packet[i] = i;
    }
    
    printf("\nSending packet...\n");
    write(uart_fd, packet, PACKET_SIZE);
    tcdrain(uart_fd); // Wait until every byte have been transmitted

    int receivedBytes = 0;
    unsigned long starttime = millis();
    while (receivedBytes < PACKET_SIZE)
    {
        if ((millis() - starttime) > 5000)
        {
            printf("Timeout occured\n");
            break;
        }
        ssize_t n = read(uart_fd, response + receivedBytes, PACKET_SIZE - receivedBytes);
        if (n > 0)
        {
            receivedBytes += n;
        }
    }
    printf("Total bytes received same as total bytes sent: %s\n", receivedBytes == PACKET_SIZE ? "True": "False");
    
    for (int i = 0; i < PACKET_SIZE; i++)
    {
        if (response[i] != i)
        {
            printf("Packet was corrupted...\n");
            close(uart_fd);
            exit(EXIT_FAILURE);
        }
    }
    printf("\nPacket was not corrupted...\n");
    close(uart_fd);

    return 0;
}

