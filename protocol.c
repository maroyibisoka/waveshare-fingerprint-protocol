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

#define BAUD_RATE_DEFAULT               19200 // Required Baud rate by the Fingerprint module
#define EIGENVALUES_LENGTH              193   //BYTES
#define TIMEOUT_DEFAULT_MS              200
#define TIMEOUT_MIN_1                   1UL * 60UL * 1000UL
#define TIMEOUT_SEC_30                  30UL * 1000UL
#define TIMEOUT_SEC_10                  10UL * 1000UL
#define BYTE_DELIMITER                  0xF5
#define CMD_IDX_PKT8                    0X01
#define P1_IDX_PKT8                     0x02
#define P2_IDX_PKT8                     0x03
#define P3_IDX_PKT8                     0x04
#define CHK_IDX_PKT8                    0X06
#define PKT_SIZE_BYTES8                 0x08
#define PKT_SIZE_BYTES207               207
#define PKT_DATA_EIGENVALUE_BYTES199    199
#define LEN                   0xC4
// Response IDX
#define RESPONSE_CODE_IDX 0x04

// int eigenvaluesStart = 8 + 4, eigenvaluesEnd = (eigenvaluesStart + EIGENVALUES_LENGTH) - 1;
#define EIGENVALUE_START_IDX        12 // 8 + 4
#define EIGENVALUE_END_IDX          204 // ((EIGENVALUE_START_IDX + EIGENVALUES_LENGTH) - 1)

// Response code
#define ACK_SUCCESS       0x00 // Operation successfully
#define ACK_FAIL          0x01 // Operation failed
#define ACK_FULL          0x04 // Fingerprint database is full
#define ACK_NOUSER        0x05 // No such user
#define ACK_USER_EXIST    0x06 // User already exists
#define ACK_FIN_EXIST     0x07 // Fingerprint already exists
#define ACK_TIMEOUT       0x08 // Acquisition timeout

// Command codes
#define CMD_ADD_FINGERPRINT             0x01
#define CMD_ACQUIRE_TOTAL_USERS         0x09
#define CMD_COMPARE_ONE_TO_ONE          0x0B
#define CMD_COMPARE_ONE_TO_N            0x0C
#define CMD_EXTRACT_EIGENVALUES         0x23
#define CMD_EXTRACT_EIGENVALUES_USERID  0x31
#define CMD_UPLOAD_EIGENVALUES_USERID   0x41
#define CMD_DELETE_SPECIFIED_USER       0x04
#define CMD_DELETE_ALL_USER             0x05

#define RESERVED_USERID_EFFECTIVENESS   0xFFF

#define DEVICE                          "/dev/ttyAMA0"

int uart_fd = -1;

unsigned long millis()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000UL) + (tv.tv_usec / 1000UL);
}


int uart_init(speed_t baud)
{
    int fd = open(DEVICE, O_RDWR | O_NOCTTY | O_NDELAY); // Non blocking mode

    if (fd == -1)
    {
        perror("Unable to open UART");
        return -1;
    }

    struct termios options;
    tcgetattr(fd, &options);

    cfmakeraw(&options);

    // Baud rate
    cfsetispeed(&options, baud);
    cfsetospeed(&options, baud);

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
    // (Matter most when specifying that the read will be in blocking mode)
    options.c_cc[VMIN] = 1;
    options.c_cc[VTIME] = 0;

    tcflush(fd, TCIFLUSH);
    tcsetattr(fd, TCSANOW, &options);
    
    uart_fd = fd;
    
    return fd;
}

int uart_close()
{
    return close(uart_fd);
}

int get_available_bytes(int fd)
{
    int bytes;
    if (ioctl(fd, FIONREAD, &bytes) == -1) {
        perror("ioctl FIONREAD");
        return -1;
    }
    return bytes;
}


// Get High 8 bits from 16 bits data
uint8_t get_high_byte(uint16_t data)
{
    return ((data & 0xFF00) >> 8);
}

// Get Low 8 bits from 16 bits data
uint8_t get_low_byte(uint16_t data)
{
    return (data & 0x00FF);
}

uint16_t combine_high_and_low_bytes(uint8_t high, uint8_t low)
{
    return ((uint16_t)high << 8) | low;
}

void display_pktn(uint8_t* pkt, int n)
{
    char buff[5];
    for (int i = 0; i < n; i++) {
        memset(buff, ' ', sizeof(buff));
        printf("%02X ", pkt[i]);
    }
    printf("\n");
}

void display_response_msg(uint8_t code)
{
    switch (code)
    {
    case ACK_SUCCESS:printf("Operation successfully\n"); break;
    case ACK_FAIL: printf("Operation failed\n"); break;
    case ACK_FULL: printf("Fingerprint database is full\n"); break;
    case ACK_NOUSER: printf("No such user\n"); break;
    case ACK_USER_EXIST: printf("User already exists\n"); break;
    case ACK_FIN_EXIST: printf("Fingerprint already exists\n"); break;
    case ACK_TIMEOUT: printf("Acquisition timeout\n"); break;
    }
}

int wait_for_response_with_timeout(int expectedBytes, int timeout)
{
    unsigned long start = millis();
    while (get_available_bytes(uart_fd) < expectedBytes)
    {
        // If timeout passed -> return 
        if ((millis() - start) > timeout)
        {
            return 0; // no response
        }
    }
    return 1;
}

int wait_for_response_with_no_timeout(int expectedBytes)
{
    unsigned long start = millis();

    while (get_available_bytes(uart_fd) < expectedBytes);
    return 1;
}

void read_response_pkt8(uint8_t* buff)
{
    read(uart_fd, buff, 8);
}
void read_response_pktn(uint8_t* buff, int n)
{
    read(uart_fd, buff, n);
}

// Compute checksum of 8 bytes packets
uint8_t compute_checksum_pkt8(uint8_t* packet)
{
    // The checksum is computed by taking the XOR
    // of the 2nd byte (index 1) to the 6th byte (index 5)
    uint8_t checksum = 0x00;
    for (int i = 1; i <= 5; i++)
    {
        checksum ^= packet[i];
    }

    return checksum;
}

uint8_t compute_checksum_pkt_n_to_n(uint8_t* packet, int start, int end)
{

    uint8_t checksum = 0x00;
    for (int i = start; i <= end; i++)
    {
        checksum ^= packet[i];
    }

    return checksum;
}
void add_checksum_pkt8(uint8_t* packet, uint8_t checksum)
{
    packet[CHK_IDX_PKT8] = checksum;
}

void initialize_pkt8(uint8_t* packet)
{
    memset(packet, 0x00, PKT_SIZE_BYTES8);
    packet[0] = BYTE_DELIMITER; // Start delimiter packet
    packet[7] = BYTE_DELIMITER; // End delimiter packet
}

void set_command_pkt8(uint8_t* packet, uint8_t command)
{
    packet[CMD_IDX_PKT8] = command;
}

void set_parameters_pkt8(uint8_t* packet, uint8_t p1, uint8_t p2, uint8_t p3)
{
    packet[P1_IDX_PKT8] = p1;
    packet[P2_IDX_PKT8] = p2;
    packet[P3_IDX_PKT8] = p3;
}


void setup_packet_data_eigenvalues(uint8_t* packetData, uint8_t* eigenvalues, uint16_t userId, uint8_t userPrivilege)
{
    packetData[0] = 0xF5;
    packetData[1] = get_high_byte(userId);
    packetData[2] = get_low_byte(userId);
    packetData[3] = userPrivilege;
    int cnt = 4;
    for (int i = 0; i < EIGENVALUES_LENGTH; i++)
    {
        packetData[cnt++] = eigenvalues[i];
    }
    int start = 1;
    int end = start + 2 + EIGENVALUES_LENGTH;
    uint8_t checksum = compute_checksum_pkt_n_to_n(packetData, start, end);
    packetData[end + 1] = checksum;
    packetData[end + 2] = 0xF5;
}

// Add fingerprint
uint8_t add_fingerprint(uint16_t userID, uint8_t userPrivilege)
{
    /*
    2.3
        (Both command and response are 8 bytes)
        To ensure the effectiveness, user must input a fingerprint three times,
        the host is required to send the command to the fingerprint module three times.
    */

    if (userPrivilege != 1 && userPrivilege != 2 && userPrivilege != 3)
    {
        // User privilege must be one of these value : 1, 2 or 3
        return ACK_FAIL;
    }

    uint8_t packet[PKT_SIZE_BYTES8];

    initialize_pkt8(packet);
    uint8_t ack = 0x00;
    for (uint8_t i = (uint8_t)CMD_ADD_FINGERPRINT; i <= 3; i++)
    {
        // Set command
        set_command_pkt8(packet, i);
        // Set User ID(high 8-bit) | User ID(low 8-bit) | User privilege(1/2/3)
        set_parameters_pkt8(packet, get_high_byte(userID), get_low_byte(userID), userPrivilege);

        // Compute checksum and add checksum to packet
        add_checksum_pkt8(packet, compute_checksum_pkt8(packet));

        write(uart_fd, packet, PKT_SIZE_BYTES8);
        tcdrain(uart_fd); // Wait until every byte have been transmitted

        int receivedBytes = 0;
        while (receivedBytes < PKT_SIZE_BYTES8)
        {
            ssize_t n = read(uart_fd, packet + receivedBytes, PKT_SIZE_BYTES8 - receivedBytes);
            if (n > 0) {
                receivedBytes += n;
            }
        }
        ack = ack || packet[RESPONSE_CODE_IDX];

    }

    return ack;
}


// Delete specified user
uint8_t delete_specified_user(uint16_t userId)
{
    /*
        2.4 Delete specified user
        (Both command and response are 8 bytes)
        Delete the fingerprint template with a specified userid
        CMD_DELETE_SPECIFIED_USER
    */

    uint8_t packet[PKT_SIZE_BYTES8];
    initialize_pkt8(packet);
    set_command_pkt8(packet, CMD_DELETE_SPECIFIED_USER);
    set_parameters_pkt8(packet, get_high_byte(userId), get_low_byte(userId), 0x00);

    add_checksum_pkt8(packet, compute_checksum_pkt8(packet));

    // Send the command packet to the fingerprint sensor
    write(uart_fd, packet, PKT_SIZE_BYTES8);
    tcdrain(uart_fd); // Wait until every byte have been transmitted

    // Receiving the response packet
    int receiveBytes = 0;
    while (receiveBytes < PKT_SIZE_BYTES8)
    {
        ssize_t n = read(uart_fd, packet + receiveBytes, PKT_SIZE_BYTES8 - receiveBytes);
        if (n > 0)
        {
            receiveBytes += n;
        }
    }
    return packet[RESPONSE_CODE_IDX];
}

// Delete all users

uint8_t delete_all_user()
{
    /*
        2.5 Delete all users
        (Both command and response are 8 bytes)
        All fingerprint template within the sensor will be deleted
        CMD_DELETE_ALL_USER

    */
    uint8_t packet[PKT_SIZE_BYTES8];
    initialize_pkt8(packet);
    set_command_pkt8(packet, CMD_DELETE_ALL_USER);
    add_checksum_pkt8(packet, compute_checksum_pkt8(packet));

    // Send the command packet to the fingerprint sensor
    write(uart_fd, packet, PKT_SIZE_BYTES8);
    tcdrain(uart_fd); // Wait until every byte have been transmitted

    // Receiving the response packet
    int receiveBytes = 0;
    while (receiveBytes < PKT_SIZE_BYTES8)
    {
        ssize_t n = read(uart_fd, packet + receiveBytes, PKT_SIZE_BYTES8 - receiveBytes);
        if (n > 0)
        {
            receiveBytes += n;
        }
    }
    return packet[RESPONSE_CODE_IDX];
}


// Acquire the total number of users
uint8_t get_total_users(uint16_t* userNumber)
{
    /*
    2.6 Acquire the total number of users (i.e no of fingerprints)
    (Both command and response are 8 bytes)
    */
    uint8_t packet[PKT_SIZE_BYTES8];

    initialize_pkt8(packet);
    set_command_pkt8(packet, CMD_ACQUIRE_TOTAL_USERS);

    // Compute checksum and add checksum to packet
    add_checksum_pkt8(packet, compute_checksum_pkt8(packet));

    // Send the command packet to the fingerprint sensor
    write(uart_fd, packet, PKT_SIZE_BYTES8);
    tcdrain(uart_fd); // Wait until every byte have been transmitted

    memset(packet, 0x00, PKT_SIZE_BYTES8);

    int receivedBytes = 0;
    while (receivedBytes < PKT_SIZE_BYTES8)
    {
        ssize_t n = read(uart_fd, packet + receivedBytes, PKT_SIZE_BYTES8 - receivedBytes);
        if (n > 0)
        {
            receivedBytes += n;
        }
    }

    *userNumber = combine_high_and_low_bytes(packet[2], packet[3]);

    return packet[RESPONSE_CODE_IDX];
}


// 2.7 Compare 1:1 (Both command and response are 8 bytes)
uint8_t compare_one_to_one(uint16_t userId)
{
    /*
    2.7
        Verifies if the finger currently on the sensor matches
        a stored template with the specified userID.
        Return
          ACK_SUCCESS  response code if matches
          ACK_FAIL     response code if no matches
          ACK_NOUSER   response code if no such user
    */

    uint8_t packet[PKT_SIZE_BYTES8];

    initialize_pkt8(packet);
    set_command_pkt8(packet, CMD_COMPARE_ONE_TO_ONE);
    set_parameters_pkt8(packet, get_high_byte(userId), get_low_byte(userId), 0x00);

    // Compute checksum and add checksum to packet
    add_checksum_pkt8(packet, compute_checksum_pkt8(packet));

    // Send the command packet to the fingerprint sensor
    write(uart_fd, packet, PKT_SIZE_BYTES8);
    tcdrain(uart_fd); // Wait until every byte have been transmitted

    int receivedBytes = 0;
    while (receivedBytes < PKT_SIZE_BYTES8)
    {
        ssize_t n = read(uart_fd, packet + receivedBytes, PKT_SIZE_BYTES8 - receivedBytes);
        if (n > 0)
        {
            receivedBytes += n;
        }
    }

    return packet[RESPONSE_CODE_IDX];
}


// 2.8 Compare 1: N
uint8_t compare_one_to_n(uint16_t* userId, uint8_t* userPrivilege)
{
    /*
    2.8 Compare 1: N
    (Both command and response are 8 bytes)
      Matches the finger currently on the sensor matches with all the template within the sensor
      Returns:
        - userID and user privilege(1/2/3) if found
        - ACK_NOUSER if no user found
        - ACK_TIMEOUT if timeout occurs
    */

    uint8_t packet[PKT_SIZE_BYTES8];

    initialize_pkt8(packet);
    set_command_pkt8(packet, CMD_COMPARE_ONE_TO_N);

    // Compute checksum and add checksum to packet
    add_checksum_pkt8(packet, compute_checksum_pkt8(packet));

    // Send the command packet to the fingerprint sensor
    write(uart_fd, packet, PKT_SIZE_BYTES8);
    tcdrain(uart_fd); // Wait until every byte have been transmitted

    int receivedBytes = 0;
    while (receivedBytes < PKT_SIZE_BYTES8)
    {
        ssize_t n = read(uart_fd, packet + receivedBytes, PKT_SIZE_BYTES8 - receivedBytes);
        if (n > 0)
        {
            receivedBytes += n;
        }
    }
    *userId = combine_high_and_low_bytes(packet[2], packet[3]);
    *userPrivilege = packet[0x04];

    if (*userPrivilege == 1 || *userPrivilege == 2 || *userPrivilege == 3)
    {
        // ACK_SUCCESS --> Operation success
        return 0;
    }

    // Operation failed
    return 1;
}


// 2.13 Upload acquired images and extracted eigenvalue (Command = 8 bytes, and response > 8bytes)
uint8_t extract_eigenvalue(uint8_t* eigenValue)
{
    /*
        Used to extract the eigenvalue from the actual fingerprint
        put on the sensor back to the micro-controller
    */
    uint8_t packet[PKT_SIZE_BYTES8];
    uint8_t response[PKT_SIZE_BYTES207];

    initialize_pkt8(packet);
    set_command_pkt8(packet, CMD_EXTRACT_EIGENVALUES);

    // Compute checksum and add checksum to packet
    add_checksum_pkt8(packet, compute_checksum_pkt8(packet));

    // Send the command packet to the fingerprint sensor
    write(uart_fd, packet, PKT_SIZE_BYTES8);
    tcdrain(uart_fd); // Wait until every byte have been transmitted

    int bytesRead = 0;
    while (bytesRead < PKT_SIZE_BYTES207)
    {
        ssize_t n = read(uart_fd, response + bytesRead, PKT_SIZE_BYTES207 - bytesRead);
        if (n > 0)
        {
            bytesRead += n;
        }
    }

    int counter = 0;
    for (size_t i = EIGENVALUE_START_IDX; i <= EIGENVALUE_END_IDX; i++)
    {
        eigenValue[counter++] = response[i];
    }

    return response[RESPONSE_CODE_IDX];
}

uint8_t extract_eigenvalue_by_user_id(uint16_t userId, uint8_t* eigenvalue)
{
    /*
    2.17
        Used to extract the eigenvalue of a specific user
        from the the sensor back to the micro-controller
        CMD: CMD_EXTRACT_EIGENVALUES_USERID  0x31
    */
    uint8_t packet[PKT_SIZE_BYTES8];
    uint8_t responseBuff[PKT_SIZE_BYTES207];
    initialize_pkt8(packet);
    set_command_pkt8(packet, CMD_EXTRACT_EIGENVALUES_USERID);
    set_parameters_pkt8(packet, get_high_byte(userId), get_low_byte(userId), 0x00);

    // Compute checksum and add checksum to packet
    add_checksum_pkt8(packet, compute_checksum_pkt8(packet));

    // Send the command packet to the fingerprint sensor
    write(uart_fd, packet, PKT_SIZE_BYTES8);
    tcdrain(uart_fd); // Wait until every byte have been transmitted

    // Receiving the response packet
    int bytesReceived = 0;
    while (bytesReceived < PKT_SIZE_BYTES207)
    {
        ssize_t n = read(uart_fd, responseBuff + bytesReceived, PKT_SIZE_BYTES207 - bytesReceived);
        if (n > 0)
        {
            bytesReceived += n;
        }
    }

    // Extracting the eigenvalue values
    int counter = 0;
    for (int i = EIGENVALUE_START_IDX; i <= EIGENVALUE_END_IDX; i++)
    {
        eigenvalue[counter++] = responseBuff[i];
    }

    return responseBuff[RESPONSE_CODE_IDX];
}

uint8_t upload_eigenvalues(uint16_t userId, uint8_t userPrivilege, uint8_t* eigenValues)
{
    /*
      2.18
      Upload the eigenvalue and save to the fingerprint sensor database according
      to the specified userId
      Packet command length > 8 bytes and Packet response length = 8 bytes
    */
    uint8_t packetHeader[PKT_SIZE_BYTES8];
    uint8_t packetData[PKT_DATA_EIGENVALUE_BYTES199];
    // Setup packet header
    initialize_pkt8(packetHeader);
    set_command_pkt8(packetHeader, CMD_UPLOAD_EIGENVALUES_USERID);
    set_parameters_pkt8(packetHeader, get_high_byte(LEN), get_low_byte(LEN), 0x00);
    // Compute checksum and add checksum to packet
    add_checksum_pkt8(packetHeader, compute_checksum_pkt8(packetHeader));

    // Setup packet data

    setup_packet_data_eigenvalues(packetData, eigenValues, userId, userPrivilege);

    uint8_t packet[PKT_SIZE_BYTES207];
    int cnt = 0;
    for (int i = 0; i < PKT_SIZE_BYTES8; i++)
    {
        packet[cnt++] = packetHeader[i];
    }
    for (int i = 0; i < PKT_DATA_EIGENVALUE_BYTES199; i++)
    {
        packet[cnt++] = packetData[i];
    }

    write(uart_fd, packet, PKT_SIZE_BYTES207);
    tcdrain(uart_fd); // Wait until every byte have been transmitted
    int receivedBytes = 0;
    while (receivedBytes < PKT_SIZE_BYTES8)
    {
        ssize_t n = read(uart_fd, packetHeader + receivedBytes, PKT_SIZE_BYTES8 - receivedBytes);
        if (n > 0)
        {
            receivedBytes += n;
        }
    }
    return packetHeader[RESPONSE_CODE_IDX];
}

uint8_t extract_eigenvalue_effectively(uint8_t userPrivilege, uint8_t* eigenValue)
{
    /*
        First add a fingerprint into the sensor with Add command to
        ensure effectiveness
        Then extract that specific fingerprint from the sensor to the database
    */
    uint8_t ack;

    // Delete the user fingerprint with userID → RESERVED_USERID_EFFECTIVENESS if exist
    ack = delete_specified_user(RESERVED_USERID_EFFECTIVENESS); // ack var here not really important
    printf("delete_specified_user ack: %d\n", ack);

    // Effectively add the fingerprint into the sensor
    ack = add_fingerprint(RESERVED_USERID_EFFECTIVENESS, userPrivilege);
    if (ack != ACK_SUCCESS)
    {
        return ack;
    }

    // Extract the eigenvalues (or template)
    ack = extract_eigenvalue_by_user_id(RESERVED_USERID_EFFECTIVENESS, eigenValue);
    if (ack != ACK_SUCCESS)
    {
        return ack;
    }

    // Delete the user fingerprint with userID → RESERVED_USERID_EFFECTIVENESS for next usage
    ack = delete_specified_user(RESERVED_USERID_EFFECTIVENESS);

    return ack;
}


// This macro check if the expr is not true (means if expression == 0) 
// --> print in stderr and abort
/*fprintf(stderr, "%s:%d: failed assertion `%s'\n", __FILE__, __LINE__, #expr); \*/
#define CHECK(receivedcode, expectedcode) \
{ \
    if (receivedcode != expectedcode) { \
        close(uart_fd); \
        fprintf(stderr, "%s:%d: failed assertion '%s == %s'\n", __FILE__, __LINE__, #receivedcode, #expectedcode); \
        fprintf(stderr, "Error code: %02X with message: ", receivedcode ); \
        display_response_msg(receivedcode); \
        fflush(stderr); \
        abort(); \
    } \
}

int main(void)
{
    uint8_t eigenValues[EIGENVALUES_LENGTH];
    uint8_t ack, userPrivilege;
    uint16_t totalUsers, userId;

    uart_fd = uart_init(BAUD_RATE_DEFAULT);
    
    if (uart_fd < 0)
    {
        exit(EXIT_FAILURE);
    }
    printf("file opened\n"); 
    get_total_users(&totalUsers);
    printf("total users: %d\n", totalUsers);
    
    ack = delete_all_user();
    printf("delete_all_user ack: %d\n", ack);

    memset(eigenValues, 0x00, EIGENVALUES_LENGTH);
    ack = extract_eigenvalue_effectively(0x01, eigenValues);
    display_pktn(eigenValues, EIGENVALUES_LENGTH);
    if (ack != ACK_SUCCESS)
    {
        return 1;
    }

    get_total_users(&totalUsers);
    printf("total users: %d\n", totalUsers);

    ack = upload_eigenvalues(0x111, 0x01, eigenValues);
    printf("upload_eigenvalues ack: %d\n", ack);
    if (ack != ACK_SUCCESS)
    {
        return 1;
    }

    sleep(5);

    ack = compare_one_to_n(&userId, &userPrivilege);
    printf("compare_one_to_n ack %d\nuserId: 0x%03X\n", ack, userId);

    ack = delete_all_user();
    printf("delete_all_user ack: %d\n", ack);
  
    close(uart_fd);
    return 0;

}
