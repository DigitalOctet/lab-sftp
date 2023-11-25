/**
 * @file auth.c
 * @author Yuhan Zhou (zhouyuhan@pku.edu.cn)
 * @brief SSH authentication layer functionalities.
 * @version 0.1
 * @date 2022-10-05
 *
 * @copyright Copyright (c) 2022
 *
 */

#include "libsftp/auth.h"

#include <stdio.h>
#include <termios.h>
#include <unistd.h>

#include "libsftp/buffer.h"
#include "libsftp/error.h"
#include "libsftp/libssh.h"
#include "libsftp/logger.h"
#include "libsftp/packet.h"
#include "libsftp/session.h"

/**
 * @brief Request server for user authentication service.
 *
 * @param session
 * @return SSH_OK on success, SSH_ERR on error.
 */
int ssh_request_auth(ssh_session session) {
    int rc;
    uint8_t type;
    char *service;

    rc = ssh_buffer_pack(session->out_buffer, "bs", SSH_MSG_SERVICE_REQUEST,
                         "ssh-userauth");
    rc |= ssh_packet_send(session);
    if (rc != SSH_OK) return rc;

    rc = ssh_packet_receive(session);
    if (rc != SSH_OK) return rc;

    rc = ssh_buffer_unpack(session->in_buffer, "bs", &type, &service);
    if (rc != SSH_OK || type != SSH_MSG_SERVICE_ACCEPT ||
        strcmp(service, "ssh-userauth") != 0) {
        SAFE_FREE(service);
        return SSH_ERROR;
    }

    SAFE_FREE(service);
    return SSH_OK;
}

/**
 * @brief Get password from terminal.
 *
 * @param password
 */
void ssh_get_password(char *password) {
    static struct termios oldt, newt;
    int max_len = 100;
    int i = 0;
    uint8_t c;

    fprintf(stdout, "password: ");
    fflush(stdout);

    /*saving the old settings of STDIN_FILENO and copy settings for resetting*/
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;

    /*setting the approriate bit in the termios struct*/
    newt.c_lflag &= ~(ECHO);

    /*setting the new bits*/
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    /*reading the password from the console*/
    while ((c = getchar()) != '\n' && c != EOF && i < max_len) {
        password[i++] = c;
    }
    password[i] = '\0';
    fprintf(stdout, "\n");
    LOG_DEBUG("Get password: %s", password);

    /*resetting our old STDIN_FILENO*/
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
}

/**
 * @brief Send password authentication requests and wait for response.
 * Can only try up to 3 times on wrong password.
 *
 * @param session
 * @param password
 * @return SSH_OK on success, SSH_ERROR on error, SSH_AGAIN on wrong password
 */
int ssh_userauth_password(ssh_session session, const char *password) {
    int rc;
    uint8_t type;
    static int cnt = 0;
    LOG_INFO("Trying password authentication...");
    rc = ssh_buffer_pack(session->out_buffer, "bsssbs",
                         SSH_MSG_USERAUTH_REQUEST, session->opts.username,
                         "ssh-connection", "password", 0, password);
    if (rc != SSH_OK) goto error;

    rc = ssh_packet_send(session);
    if (rc != SSH_OK) goto error;

    /**
     * RFC 4252 5.4
     * The SSH server may send an SSH_MSG_USERAUTH_BANNER message at any
     * time after this authentication protocol starts and before
     * authentication is successful.  This message contains text to be
     * displayed to the client user before authentication is attempted.
     *
     */

    while (rc != SSH_ERROR) {
        rc = ssh_packet_receive(session);
        if (rc != SSH_OK) goto error;
        ssh_buffer_get_u8(session->in_buffer, &type);
        switch (type) {
            case SSH_MSG_USERAUTH_BANNER:
                // LAB: insert your code here.
                // Packet format:
                // byte      SSH_MSG_USERAUTH_BANNER
                // string    message in ISO-10646 UTF-8 encoding [RFC3629]
                // string    language tag [RFC3066]
                char *message, *language_tag;
                rc = ssh_buffer_unpack(session->in_buffer, "ss", &message,
                                       &language_tag);
                if (rc != SSH_OK) goto error;
                LOG_INFO("Message: %s", message);
                LOG_INFO("Language tag: %s", language_tag);
                break;
            case SSH_MSG_USERAUTH_SUCCESS:
                // LAB: insert your code here.
                LOG_NOTICE("Authentication success!");
                return SSH_OK;
            case SSH_MSG_USERAUTH_PASSWD_CHANGEREQ:
                LOG_INFO("Password change required!");
                return SSH_ERROR;
            case SSH_MSG_USERAUTH_FAILURE:
                // LAB: insert your code here.
                // Packet format:
                // byte         SSH_MSG_USERAUTH_FAILURE
                // name-list    authentications that can continue
                // boolean      partial success

                // // Get name-list.
                // char *auth_methods = NULL;
                // rc = ssh_buffer_unpack(session->in_buffer, "s",
                //                        &auth_methods);
                // if (rc != SSH_OK) goto error;
                // LOG_DEBUG("auth_methods: %s", auth_methods);

                // // Get partial success.
                // uint8_t partial_success;
                // rc = ssh_buffer_unpack(session->in_buffer, "b", &partial_success);
                // if (rc != SSH_OK) goto error;
                // LOG_DEBUG("partial_success: %d", partial_success);
                LOG_INFO("Permission denied, please try again.");
                return SSH_AGAIN;
            default:
                // LAB: insert your code here.
                LOG_DEBUG("Unknown packet type %d", type);
                break;
        }
    }

error:
    LOG_DEBUG("Error");
    ssh_buffer_reinit(session->out_buffer);
    return SSH_ERROR;
}