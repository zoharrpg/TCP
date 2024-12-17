/**
 * Copyright (C) 2022 Carnegie Mellon University
 *
 * This file is part of the TCP in the Wild course project developed for the
 * Computer Networks course (15-441/641) taught at Carnegie Mellon University.
 *
 * No part of the project may be copied and/or distributed without the express
 * permission of the 15-441/641 course staff.
 *
 *
 * This file implements the CMU-TCP backend. The backend runs in a different
 * thread and handles all the socket operations separately from the application.
 *
 * This is where most of your code should go. Feel free to modify any function
 * in this file.
 */

#include "backend.h"

#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>

#include "cmu_packet.h"
#include "cmu_tcp.h"

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
#define SYN_ACK_FLAG_MASK (SYN_FLAG_MASK + ACK_FLAG_MASK)

/**
 * Tells if a given sequence number has been acknowledged by the socket.
 *
 * @param sock The socket to check for acknowledgements.
 * @param seq Sequence number to check.
 *
 * @return 1 if the sequence number has been acknowledged, 0 otherwise.
 */
int has_been_acked(cmu_socket_t *sock, uint32_t seq) {
  int result;
  result = after(sock->window.last_ack_received, seq);
  return result;
}

void init_packet_list(packet_list_t* list) {
    list->head = NULL;  // Initialize head pointer to NULL
    list->end = NULL;   // Initialize end pointer to NULL
    list->size = 0;     // Initialize size to 0
}


void add_packet(packet_list_t* list, uint8_t* packet, uint32_t seq_num, uint64_t send_time) {
    sent_packet_t* new_packet = (sent_packet_t*)malloc(sizeof(sent_packet_t));
    if (new_packet == NULL) {
        printf("Memory allocation failed\n");
        return;
    }

    new_packet->packet = packet;
    new_packet->seq_num = seq_num;
    new_packet->send_time = send_time;
    new_packet->next = NULL;
    new_packet->prev = list->end;

    if (list->end == NULL) {
        // If the list is empty, initialize both head and end to new packet
        list->head = new_packet;
        list->end = new_packet;
    } else {
        // Update the current end's next to new packet
        list->end->next = new_packet;
        list->end = new_packet;
    }

    // Increment the list size
    list->size+=get_plen((cmu_tcp_header_t*)packet);
}

void add_window(cmu_socket_t *sock,uint8_t* packet, uint32_t seq_num, uint64_t send_time) {
    if (sock->window_list.size < sock->window_size) {
        // Add packet to the window list if it has not reached the window size limit
        add_packet(&sock->window_list, packet, seq_num, send_time);
    } else {
        // Add packet to the packet list if window list has reached its size limit
        add_packet(&sock->packetList, packet, seq_num, send_time);
    }
}
sent_packet_t* pop_head_packet(packet_list_t* list) {
    if (list->head == NULL) {
        // List is empty, nothing to pop
        return NULL;
    }

    // Get the current head
    sent_packet_t* head_packet = list->head;

    // Update the head to the next packet in the list
    list->head = head_packet->next;

    if (list->head != NULL) {
        // If there's a new head, set its previous pointer to NULL
        list->head->prev = NULL;
    } else {
        // If the list is now empty, update the end pointer as well
        list->end = NULL;
    }

    // Decrement the list size
    list->size-= get_plen((cmu_tcp_header_t*)head_packet->packet);

    // Disconnect the popped packet from the list
    head_packet->next = NULL;
    head_packet->prev = NULL;

    return head_packet; // Return the popped packet
}

sent_packet_t* pop_from_window(cmu_socket_t *sock) {
    // Pop the head packet from the window list
    sent_packet_t* removed_packet = pop_head_packet(&sock->window_list);

    // If packet_list is not empty, move its head to the end of window_list
    if (sock->packetList.head != NULL) {
        // Pop the head of packet_list
        sent_packet_t* packet_to_move = pop_head_packet(&sock->packetList);

        if (packet_to_move != NULL) {
            // Use add_packet to add this packet at the end of window_list
            add_packet(&sock->window_list, packet_to_move->packet, packet_to_move->seq_num, packet_to_move->send_time);

            // Free the packet_to_move node, but not its packet data (as it's now in window_list)
            free(packet_to_move);
        }
    }

    // Return the removed packet from window_list
    return removed_packet;
}

void remove_packets_before(cmu_socket_t *sock, uint32_t seq_num) {
    sent_packet_t* removed_packet = NULL;

    // Continue removing packets from the head of window_list if their seq_num is less than the provided value
    while (sock->window_list.head != NULL && sock->window_list.head->seq_num < seq_num) {
        // Use pop_from_window to remove the head packet from window_list
        removed_packet = pop_from_window(sock);

        // Free the packet data within the removed packet
        if (removed_packet != NULL) {
            if (removed_packet->packet != NULL) {
                free(removed_packet->packet);
            }
            free(removed_packet); // Free the removed node
        }
    }
}

uint8_t *create_empty_packet(cmu_socket_t *sock, uint32_t seq_number,uint32_t ack_number, uint8_t tcp_flags,uint16_t tcp_adv_window){

    uint8_t *payload = NULL;
    uint16_t payload_len = 0;

    uint16_t src = sock->my_port;
    uint16_t dst = ntohs(sock->conn.sin_port);

    uint32_t seq = seq_number;
    uint32_t ack = ack_number;

    uint16_t hlen = sizeof(cmu_tcp_header_t);
    uint16_t plen = hlen;

    uint8_t flags = tcp_flags;
    uint16_t adv_window = tcp_adv_window;

    uint16_t ext_len = 0;
    uint8_t *ext_data = NULL;

    uint8_t *packet = create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window, ext_len,
                          ext_data, payload, payload_len);
    return packet;
}

uint64_t current_time(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    uint64_t milliseconds = (uint64_t)(ts.tv_sec) * 1000 + ts.tv_nsec / 1000000;;
    return milliseconds;
}

/**
 * Updates the socket information to represent the newly received packet.
 *
 * In the current stop-and-wait implementation, this function also sends an
 * acknowledgement for the packet.
 *
 * @param sock The socket used for handling packets received.
 * @param pkt The packet data received by the socket.
 */
void handle_message(cmu_socket_t *sock, uint8_t *pkt) {
    cmu_tcp_header_t *hdr = (cmu_tcp_header_t *)pkt;

    uint8_t flags = get_flags(hdr);

    socklen_t conn_len = sizeof(sock->conn);

    switch (sock->state) {
        case ESTABLISHED:
            printf("Come to establish state\n");



            uint32_t ack_rec = get_ack(hdr);

            printf("The flag is %d\n", get_flags(hdr));
            printf("ack number %d\n",ack_rec);
            printf("window.last ack received numeber %d\n",sock->window.last_ack_received);

            if(flags == SYN_ACK_FLAG_MASK && sock->ISN+1== get_ack(hdr)){
                uint32_t  ack_number = get_seq(hdr) + 1;
                sock->next_sent = sock->ISN+1;
                sock->window.next_seq_expected = get_seq(hdr)+1;
                sock->window_size = get_advertised_window(hdr);
                sock->window.last_ack_received = get_ack(hdr);

                uint8_t  *new_ack_msg = create_empty_packet(sock,sock->ISN,ack_number,ACK_FLAG_MASK,CP1_WINDOW_SIZE);
                sendto(sock->socket, new_ack_msg, sizeof(cmu_tcp_header_t), 0,(struct sockaddr *)&(sock->conn), conn_len);
                free(new_ack_msg);
            }

            if(flags == ACK_FLAG_MASK && after(ack_rec,sock->window.last_ack_received)){
                remove_packets_before(sock,ack_rec);
                sock->window.last_ack_received = ack_rec;
            }

            if(get_payload_len(pkt)>0){

                //printf("data case\n");

                uint32_t rec_seq = get_seq(hdr);



                //printf("%d\n",rec_seq);
                //printf("%d\n",sock->window.next_seq_expected);

                if (rec_seq <= sock->window.next_seq_expected) {
//                    if(sock->type == TCP_LISTENER){
//                        exit(0);
//                    }

                    //printf("sent ack\n");
                   //seq = 0;
                    uint8_t *payload = NULL;
                    uint16_t payload_len = 0;

                    // No extension.

                    uint16_t ext_len = 0;
                    uint8_t *ext_data = NULL;

                    uint16_t src = sock->my_port;
                    uint16_t dst = ntohs(sock->conn.sin_port);
                    uint32_t ack_local = rec_seq + get_payload_len(pkt);
                    uint16_t hlen = sizeof(cmu_tcp_header_t);
                    uint16_t plen = hlen + payload_len;
                    uint8_t flag = ACK_FLAG_MASK;
                    uint16_t adv_window = CP1_WINDOW_SIZE;
                    uint8_t *response_packet = create_packet(src, dst, 0, ack_local, hlen, plen, flag, adv_window,ext_len, ext_data, payload, payload_len);

                    sendto(sock->socket, response_packet, plen, 0,(struct sockaddr *)&(sock->conn), conn_len);

                    free(response_packet);

                    if(rec_seq == sock->window.next_seq_expected){
                        sock->window.next_seq_expected += get_payload_len(pkt);

                        payload_len = get_payload_len(pkt);

                        payload = get_payload(pkt);

                        // Make sure there is enough space in the buffer to store the payload.
                        sock->received_buf = realloc(sock->received_buf, sock->received_len + payload_len);
                        memcpy(sock->received_buf + sock->received_len, payload, payload_len);
                        sock->received_len += payload_len;

                    }
                }


            }
            break;
        default:
            printf("other state here\n");
            break;
    }
}

/**
 * Checks if the socket received any data.
 *
 * It first peeks at the header to figure out the length of the packet and then
 * reads the entire packet.
 *
 * @param sock The socket used for receiving data on the connection.
 * @param flags Flags that determine how the socket should wait for data. Check
 *             `cmu_read_mode_t` for more information.
 */
void check_for_data(cmu_socket_t *sock, cmu_read_mode_t flags) {
  cmu_tcp_header_t hdr;
  uint8_t *pkt;
  socklen_t conn_len = sizeof(sock->conn);
  ssize_t len = 0;
  uint32_t plen = 0, buf_size = 0, n = 0;

  while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
  }
  switch (flags) {
    case NO_FLAG:
      len = recvfrom(sock->socket, &hdr, sizeof(cmu_tcp_header_t), MSG_PEEK,
                     (struct sockaddr *)&(sock->conn), &conn_len);
      break;
    case TIMEOUT: {
      // Using `poll` here so that we can specify a timeout.
      struct pollfd ack_fd;
      ack_fd.fd = sock->socket;
      ack_fd.events = POLLIN;
      // Timeout after DEFAULT_TIMEOUT.
      if (poll(&ack_fd, 1, DEFAULT_TIMEOUT) <= 0) {
        break;
      }
    }
    // Fallthrough.
    case NO_WAIT:
      len = recvfrom(sock->socket, &hdr, sizeof(cmu_tcp_header_t),
                     MSG_DONTWAIT | MSG_PEEK, (struct sockaddr *)&(sock->conn),
                     &conn_len);
      break;
    default:
      perror("ERROR unknown flag");
  }
  if (len >= (ssize_t)sizeof(cmu_tcp_header_t)) {
    plen = get_plen(&hdr);
    pkt = malloc(plen);
    while (buf_size < plen) {
      n = recvfrom(sock->socket, pkt + buf_size, plen - buf_size, 0,
                   (struct sockaddr *)&(sock->conn), &conn_len);
      buf_size = buf_size + n;
    }
    handle_message(sock, pkt);
    free(pkt);
  }
  pthread_mutex_unlock(&(sock->recv_lock));
}

uint8_t *receive_handshake(cmu_socket_t *sock, cmu_read_mode_t flags) {
    cmu_tcp_header_t hdr;
    uint8_t *pkt = NULL;
    socklen_t conn_len = sizeof(sock->conn);
    ssize_t len = 0;
    uint32_t plen = 0, buf_size = 0, n = 0;

    while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
    }
    switch (flags) {
        case NO_FLAG:
            len = recvfrom(sock->socket, &hdr, sizeof(cmu_tcp_header_t), MSG_PEEK,
                           (struct sockaddr *)&(sock->conn), &conn_len);
            break;
        case TIMEOUT: {
            // Using `poll` here so that we can specify a timeout.
            struct pollfd ack_fd;
            ack_fd.fd = sock->socket;
            ack_fd.events = POLLIN;
            // Timeout after DEFAULT_TIMEOUT.
            if (poll(&ack_fd, 1, DEFAULT_TIMEOUT) <= 0) {
                break;
            }
        }
            // Fallthrough.
        case NO_WAIT:
            len = recvfrom(sock->socket, &hdr, sizeof(cmu_tcp_header_t),
                           MSG_DONTWAIT | MSG_PEEK, (struct sockaddr *)&(sock->conn),
                           &conn_len);
            break;
        default:
            perror("ERROR unknown flag");
    }
    if (len >= (ssize_t)sizeof(cmu_tcp_header_t)) {
        plen = get_plen(&hdr);
        pkt = malloc(plen);
        while (buf_size < plen) {
            n = recvfrom(sock->socket, pkt + buf_size, plen - buf_size, 0,
                         (struct sockaddr *)&(sock->conn), &conn_len);
            buf_size = buf_size + n;
        }
    }
    pthread_mutex_unlock(&(sock->recv_lock));
    return pkt;
}

/**
 * Breaks up the data into packets and sends a single packet at a time.
 *
 * You should most certainly update this function in your implementation.
 *
 * @param sock The socket to use for sending data.
 * @param data The data to be sent.
 * @param buf_len The length of the data being sent.
 */
void single_send(cmu_socket_t *sock, uint8_t *data, int buf_len) {
    uint8_t *msg;
    uint8_t *data_offset = data;

    size_t conn_len = sizeof(sock->conn);
    int sockfd = sock->socket;

    if (buf_len > 0) {
        while (buf_len != 0) {
            uint16_t payload_len = MIN((uint32_t)buf_len, (uint32_t)MSS);
            uint16_t src = sock->my_port;
            uint16_t dst = ntohs(sock->conn.sin_port);
            uint32_t seq = sock->next_sent;
            sock->next_sent+=payload_len;
            uint32_t ack = sock->window.next_seq_expected;
            uint16_t hlen = sizeof(cmu_tcp_header_t);
            uint16_t plen = hlen + payload_len;
            uint8_t flags = ACK_FLAG_MASK;
            uint16_t adv_window = CP1_WINDOW_SIZE;
            uint16_t ext_len = 0;
            uint8_t *ext_data = NULL;
            uint8_t *payload = data_offset;

            msg = create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window, ext_len, ext_data, payload, payload_len);
            buf_len -= payload_len;

            if(sock->window_list.size < sock->window_size){
                sendto(sockfd, msg, plen, 0, (struct sockaddr *)&(sock->conn),
                       conn_len);
            }
            // add to the queue
            //add_packet(&sock->window_list,msg,seq,current_time());

            add_window(sock,msg,seq,current_time());

//            if(sock->window_list.size>0){
//                printf("add success\n");
//            }else{
//                printf("add false\n");
//            }

            data_offset += payload_len;
        }
    }
}


void retransmit(cmu_socket_t *sock) {
    sent_packet_t* current = sock->window_list.head;
    uint64_t current_time_stamp = current_time();

    // Traverse the window list and perform the operation on each packet
    while (current != NULL) {
        if( (current_time_stamp - current->send_time) >= DEFAULT_TIMEOUT){
            printf("actual Retransmit\n");


            size_t test = sendto(sock->socket, current->packet, get_plen((cmu_tcp_header_t *)current->packet), 0, (struct sockaddr *)&(sock->conn),sizeof(sock->conn));
            printf("The send to is %zu\n",test);

            current->send_time = current_time_stamp;

            check_for_data(sock,NO_WAIT);
        }
        current = current->next;
    }
}



void client_handshake(cmu_socket_t *sock){
    int sockfd = sock->socket;
    uint32_t seq = sock->next_sent;
    uint32_t ack_number = 0;
    uint8_t *msg = create_empty_packet(sock,seq,ack_number,SYN_FLAG_MASK,CP1_WINDOW_SIZE);
    size_t conn_len = sizeof(sock->conn);

    sock->next_sent++;
    sock->state = SYN_SENT;

    while(1){
        sendto(sockfd, msg, sizeof(cmu_tcp_header_t), 0,
               (struct sockaddr *)&(sock->conn), conn_len);

        uint8_t *handshake = receive_handshake(sock,TIMEOUT);
        if(handshake){
            cmu_tcp_header_t *hdr = (cmu_tcp_header_t *)handshake;
            if (get_flags(hdr) == SYN_ACK_FLAG_MASK &&  sock->window.last_ack_received+1== get_ack(hdr)) {
                ack_number = get_seq(hdr) + 1;
                sock->window.next_seq_expected = get_seq(hdr)+1;
                sock->window_size = get_advertised_window(hdr);
                sock->window.last_ack_received = get_ack(hdr);
                free(handshake);
                sock->state = ESTABLISHED;
                break;
            }
            free(handshake);
        }

    }
    free(msg);

    msg = create_empty_packet(sock,seq,ack_number,ACK_FLAG_MASK,CP1_WINDOW_SIZE);



    sendto(sockfd, msg, sizeof(cmu_tcp_header_t), 0,(struct sockaddr *)&(sock->conn), conn_len);
    free(msg);

    init_packet_list(&sock->window_list);
    init_packet_list(&sock->packetList);
}

void server_handshake(cmu_socket_t *sock){
    uint8_t *msg = NULL;
    int sockfd = sock->socket;
    size_t conn_len = sizeof(sock->conn);
    uint32_t ack_number = 0;
    uint32_t seq = sock->next_sent;

    while(1){
        uint8_t *pkt = receive_handshake(sock, TIMEOUT);
        if (pkt) {
            cmu_tcp_header_t *hdr = (cmu_tcp_header_t *)pkt;
            if (get_flags(hdr) == SYN_FLAG_MASK) {

                ack_number = get_seq(hdr) + 1;
                sock->window.next_seq_expected = ack_number;
                free(pkt);
                sock->state = LISTEN;
                break;
            }
            free(pkt);
        }

    }
    msg = create_empty_packet(sock,seq,sock->window.next_seq_expected,SYN_ACK_FLAG_MASK,CP1_WINDOW_SIZE);

    sock->next_sent++;

    while(1){
        sendto(sockfd, msg, sizeof(cmu_tcp_header_t), 0,
               (struct sockaddr *)&(sock->conn), conn_len);
        uint8_t *pkt = receive_handshake(sock, TIMEOUT);
        if (pkt) {
            cmu_tcp_header_t *hdr = (cmu_tcp_header_t *)pkt;
            if (get_flags(hdr) == ACK_FLAG_MASK) {
                sock->state = ESTABLISHED;
                sock->window.last_ack_received = get_ack(hdr);
                free(pkt);
                break;
            }
            free(pkt);
        }
    }
    free(msg);
    init_packet_list(&sock->window_list);
    init_packet_list(&sock->packetList);
}
void *begin_backend(void *in) {
    cmu_socket_t *sock = (cmu_socket_t *) in;
    int death, buf_len, send_signal;
    uint8_t *data;
//    int sockfd = sock->socket;
//    size_t conn_len = sizeof(sock->conn);

    if (sock->type == TCP_INITIATOR) {
        client_handshake(sock);

    }else{
        server_handshake(sock);
    }

    printf("The init window %d\n",sock->window_size);

    while(1) {

        switch (sock->state) {
            case ESTABLISHED:
                //printf("begin establish\n");
                while (pthread_mutex_lock(&(sock->death_lock)) != 0) {

                }
                death = sock->dying;

                pthread_mutex_unlock(&(sock->death_lock));

                while (pthread_mutex_lock(&(sock->send_lock)) != 0) {

                }
                buf_len = sock->sending_len;

                if (death && buf_len == 0) {
                    break;

                }

                if (buf_len > 0) {
                    //printf("sending packet\n");
                    data = malloc(buf_len);
                    memcpy(data, sock->sending_buf, buf_len);
                    sock->sending_len = 0;
                    free(sock->sending_buf);
                    sock->sending_buf = NULL;
                    pthread_mutex_unlock(&(sock->send_lock));

                    single_send(sock, data, buf_len);



                    free(data);

                }else {
                    pthread_mutex_unlock(&(sock->send_lock));
                }

                check_for_data(sock, NO_WAIT);

                retransmit(sock);

                //printf("transmit call\n");

                while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {}

                send_signal = sock->received_len > 0;
//                        || sock->window_list.size > 0;

                pthread_mutex_unlock(&(sock->recv_lock));
                if (send_signal) {
                    pthread_cond_signal(&(sock->wait_cond));
                }
                break;

            default:
                printf("State error\n");
                break;

        }

    }
    pthread_exit(NULL);
    return NULL;
}
