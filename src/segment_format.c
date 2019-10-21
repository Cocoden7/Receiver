#include "packet_interface.h"
#include <stddef.h> /* size_t */
#include <stdint.h> /* uintx_t */
#include <stdio.h>  /* ssize_t */
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <zlib.h>
/* Your code will be inserted here */

struct __attribute__((__packed__)) pkt {
    ptypes_t type;
    uint8_t tr;
    uint8_t window;
    uint8_t l;
    uint16_t length;
    uint8_t seqnum;
    uint32_t timestamp;
    uint32_t crc1;
    char *payload;
    uint32_t crc2;
};

/* Extra code */
/* Your code will be inserted here */

pkt_t* pkt_new()
{
    pkt_t *packet = malloc(sizeof(pkt_t));
    if(packet == NULL){
        return NULL;
    }
    return packet;
}

void pkt_del(pkt_t *pkt)
{
    if(pkt->payload != NULL)
    {
        free(pkt->payload);
    }
    free(pkt);
    /* Your code will be inserted here */
}
/*
 * Decode des donnees recues et cree une nouvelle structure pkt.
 * Le paquet recu est en network byte-order.
 * La fonction verifie que:
 * - Le CRC32 du header recu est le mÃƒÂªme que celui decode a la fin
 *   du header (en considerant le champ TR a 0)
 * - S'il est present, le CRC32 du payload recu est le meme que celui
 *   decode a la fin du payload
 * - Le type du paquet est valide
 * - La longueur du paquet et le champ TR sont valides et coherents
 *   avec le nombre d'octets recus.
 *
 * @data: L'ensemble d'octets constituant le paquet recu
 * @len: Le nombre de bytes recus
 * @pkt: Une struct pkt valide
 * @post: pkt est la representation du paquet recu
 *
 * @return: Un code indiquant si l'operation a reussi ou representant
 *         l'erreur rencontree.
 */
pkt_status_code pkt_decode(const char *data, const size_t len, pkt_t *pkt)
{
    // Header trop court
    ssize_t header_size = predict_header_length(pkt);
    if(header_size < 7)
    {
        return E_NOHEADER;
    }

    // Longueur du paquet incohérente
    if(len != (2 + 1 + 5 + 1 + 7 + 32 + 32) / 8 || len != (2 + 1 + 5 + 1 + 15 + 32 + 32) / 8)
    {
        return E_UNCONSISTENT;
    }

    // Set type
    if(pkt_set_type(pkt, (uint8_t) data[0]>>6) == E_TYPE)
    {
        return E_TYPE;
    }

    // Set tr
    if(pkt_set_tr(pkt, (uint8_t) (data[0]<<2)>>7) == E_TR)
    {
        return E_TR;
    }

    // Ce cas produit une erreur
    if(pkt->tr==1 && pkt->type !=PTYPE_DATA) {
        return E_TR;
    }

    // Set window
    if(pkt_set_window(pkt, (uint8_t) (data[0]<<3)>>3) == E_WINDOW)
    {
        return E_WINDOW;
    }

    // Set l et length
    uint8_t l = data[1]>>7;
    pkt->l = l;
    if(l == 0)
    {
        if(pkt_set_length(pkt, (uint16_t) ((data[1])<<1)>>1) == E_LENGTH)
        {
            return E_LENGTH;
        }
    }
    else
    {
        if(pkt_set_length(pkt, ((uint16_t)((data[1])<<1)>>1)<<8 | (uint16_t)data[2]))
        {
            return E_LENGTH;
        }
    }

    // Set seqnum
    if(pkt_set_seqnum(pkt, (uint8_t)data[2 + l]) == E_SEQNUM)
    {
        return E_SEQNUM;
    }

    // Set timestamp
    uint32_t *data32 = malloc(sizeof(uint32_t));
    memcpy(data32, &data[3 + l], 4);
    pkt_set_timestamp(pkt, *data32);

    // Set and check crc1
    memcpy(data32, &data[7 + l], 4);
    pkt_set_crc1(pkt, *data32);
    uint8_t *header = malloc(header_size);
    memcpy(header, data, header_size);
    uint32_t checkCrc1 = crc32(0, Z_NULL, 0);
    checkCrc1 = crc32(checkCrc1, header, header_size);
    // CRC1 invalide
    if(checkCrc1 != pkt_get_crc1(pkt))
    {
        return E_CRC;
    }
    char *data_payload = malloc(sizeof(char)*pkt->length);

    // Set payload et crc2 avec length sur 7 bits
    if(pkt->tr == 0)
    {
        memcpy(data_payload, &data[8 + l], pkt->length);
        pkt_set_payload(pkt, data_payload, pkt->length);
        pkt_set_crc2(pkt, data[11+pkt->length]);
    }

    // Set payload et crc2 avec length sur 15 bits
    else 
    {
        pkt_set_payload(pkt, NULL, 0);
        pkt_set_crc2(pkt, data[12+pkt->length]);
    }

    // Check crc2
    uint32_t checkCrc2 = crc32(0L, Z_NULL, 0);
    if(pkt->payload != NULL && pkt->tr == 0 && pkt->type == PTYPE_DATA)
    {
        checkCrc2 = crc32(checkCrc2, (uint8_t *) pkt_get_payload(pkt), pkt_get_length(pkt));
        if(checkCrc2 != pkt_get_crc2(pkt))
        {
            return E_CRC;
        }
    }

    return PKT_OK;
}



/*
 * Encode une struct pkt dans un buffer, prêt a être envoyé sur le reseau
 * (c-a-d en network byte-order), incluant le CRC32 du header et
 * eventuellement le CRC32 du payload si celui-ci est non nul.
 *
 * @pkt: La structure a encoder
 * @buf: Le buffer dans lequel la structure sera encodee
 * @len: La taille disponible dans le buffer
 * @len-POST: Le nombre de d'octets ecrit dans le buffer
 * @return: Un code indiquant si l'operation a reussi ou E_NOMEM si
 *         le buffer est trop petit.
 */
pkt_status_code pkt_encode(const pkt_t* pkt, char *buf, size_t *len)
{
    size_t size = predict_header_length(pkt);
    // Le buffer est trop petit
    if(*len < size)
    {
        return E_NOMEM;
    }
    // Encode byte par byte
    buf[0] = pkt_get_type(pkt)<<6 | pkt_get_tr(pkt)<<5 | pkt_get_window(pkt);
    // Length sur 7 bits
    if (pkt->l == 0)
    {
        buf[1] = pkt->l<<7 | pkt_get_length(pkt);
        buf[2] = pkt_get_seqnum(pkt);
        buf[3] = pkt_get_timestamp(pkt);
        buf[7] = pkt_get_crc1(pkt);
        memcpy(&buf[11], pkt_get_payload(pkt), pkt_get_length(pkt));
        buf[11+pkt_get_length(pkt)] = pkt_get_crc2(pkt);

    }
    // Length sur 15 bits
    else
    {
        buf[1] = pkt->l<<7 | pkt_get_length(pkt)>>8;
        buf[2] = pkt_get_length(pkt) & 0b111111111;
        buf[3] = pkt_get_seqnum(pkt);
        buf[4] = pkt_get_timestamp(pkt);
        buf[8]= pkt_get_crc1(pkt);
        memcpy(&buf[12], pkt_get_payload(pkt), pkt_get_length(pkt));
        buf[12+pkt_get_length(pkt)] = pkt_get_crc2(pkt);
    }

    return PKT_OK;
}

ptypes_t pkt_get_type  (const pkt_t* pkt)
{
    return pkt->type;
}

uint8_t  pkt_get_tr(const pkt_t* pkt)
{
    return pkt->tr;
}

uint8_t  pkt_get_window(const pkt_t* pkt)
{
    return pkt->window;
}

uint8_t  pkt_get_seqnum(const pkt_t* pkt)
{
    return pkt->seqnum;
}

uint16_t pkt_get_length(const pkt_t* pkt)
{
    return pkt->length;
}

uint32_t pkt_get_timestamp   (const pkt_t* pkt)
{
    return pkt->timestamp;
}

uint32_t pkt_get_crc1   (const pkt_t* pkt)
{
    return pkt->crc1;
}

uint32_t pkt_get_crc2   (const pkt_t* pkt)
{
    return pkt->crc2;
}

const char* pkt_get_payload(const pkt_t* pkt)
{
    return pkt->payload;
}


pkt_status_code pkt_set_type(pkt_t *pkt, const ptypes_t type)
{ 
    if(type == 1 || type == 2 || type == 3){
        pkt->type = type;
        return PKT_OK;
    }
    return E_TYPE;
}

pkt_status_code pkt_set_tr(pkt_t *pkt, const uint8_t tr)
{
    if(tr == 0 || tr == 1){
        pkt->tr = tr;
        return PKT_OK;
    }
    return E_TR;

}

pkt_status_code pkt_set_window(pkt_t *pkt, const uint8_t window)
{
    pkt->window = window;
    return PKT_OK;
}

// Comment on pourrait avoir un E_SEQNUM?
pkt_status_code pkt_set_seqnum(pkt_t *pkt, const uint8_t seqnum)
{
    pkt->seqnum = seqnum;
    return PKT_OK;
}

pkt_status_code pkt_set_length(pkt_t *pkt, const uint16_t length)
{
    if(length > 512)
    {
        return E_LENGTH;
    }
    pkt->length = length;
    return PKT_OK;
}


pkt_status_code pkt_set_timestamp(pkt_t *pkt, const uint32_t timestamp)
{
    pkt->timestamp = timestamp;
    return PKT_OK;
}

// Comment on peut avoir une erreur?
pkt_status_code pkt_set_crc1(pkt_t *pkt, const uint32_t crc1)
{
    pkt->crc1 = crc1;
    return PKT_OK;
}

// Comment on peut avoir une erreur?
pkt_status_code pkt_set_crc2(pkt_t *pkt, const uint32_t crc2)
{
    pkt->crc2 = crc2;
    return PKT_OK;
}

pkt_status_code pkt_set_payload(pkt_t *pkt,
                                const char *data,
                                const uint16_t length)
{
    if(pkt_set_length(pkt, length) == E_LENGTH)
    {
        return E_LENGTH;
    }
    memcpy(pkt->payload, data, length);
    return PKT_OK;

}
    


/*
 * Decode un varuint (entier non signe de taille variable  dont le premier bit indique la longueur)
 * encode en network byte-order dans le buffer data disposant d'une taille maximale len.
 * @post: place Ã  l'adresse retval la valeur en host byte-order de l'entier de taille variable stocke
 * dans data si aucune erreur ne s'est produite
 * @return:
 *
 *          -1 si data ne contient pas un varuint valide (la taille du varint
 * est trop grande par rapport Ã  la place disponible dans data)
 *
 *          le nombre de bytes utilises si aucune erreur ne s'est produite
 */

// A CHECKER
ssize_t varuint_decode(const uint8_t *data, const size_t len, uint16_t *retval)
{
    size_t varuint_l = varuint_len(data);
    // Varuint trop grand
    if(varuint_l > len)
    {
        return -1;
    }
    // Varuint sur 1 byte
    else if(varuint_l == 1)
    {
        *retval = (data[0]<<1)>>1;
    }
    // Varuint sur 2 bytes
    else if(varuint_l == 2)
    {
        uint16_t *data2 = malloc(len);
        memcpy(data2, data, 2);
        data2[0] =  (data2[0]<<1)>>1; // Car le premier bit indique la taille
        *data2 = htons(*data2);
        memcpy(retval, data2, 2);
    }
    else
    {
        return -1;
    }
    return varuint_l;
}

/*
 * Encode un varuint en network byte-order dans le buffer data disposant d'une
 * taille maximale len.
 * @pre: val < 0x8000 (val peut Ãªtre encode en varuint)
 * @return:
 *           -1 si data ne contient pas une taille suffisante pour encoder le varuint
 *
 *           la taille necessaire pour encoder le varuint (1 ou 2 bytes) si aucune erreur ne s'est produite
 */
ssize_t varuint_encode(uint16_t val, uint8_t *data, const size_t len)
{
    ssize_t encode_size = varuint_predict_len(val);
    size_t sencode_size = (size_t) encode_size;
    // Varuint trop grand
    if(len < sencode_size || encode_size == -1)
    {
        return -1;
    }
    // Varuint sur 1 byte
    if(encode_size == 1)
    {
        data[0] = val;
    }
    // Varuint sur 2 bytes
    else
    {
        data[0] = (val >> 8);
        data[1] = val & 0xff;
    }
    return encode_size;
}

/*
 * @pre: data pointe vers un buffer d'au moins 1 byte
 * @return: la taille en bytes du varuint stocke dans data, soit 1 ou 2 bytes.
 */
size_t varuint_len(const uint8_t *data)
{
    if(data[0]>>7 == 0)
    {
        return 1;
    }
    else
    {
        return 2;
    }
}

/*
 * @return: la taille en bytes que prendra la valeur val
 * une fois encodee en varuint si val contient une valeur varuint valide (val < 0x8000).
            -1 si val ne contient pas une valeur varuint valide
 */
ssize_t varuint_predict_len(uint16_t val)
{
    // Val >= 0x8000
    if(val >= 32768) // 0x8000 = 32768
    {
        return -1;
    }
    // 1 byte
    else if(val <= 255)
    {
        return 1;
    }
    // 2 bytes
    else
    {
        return 2;
    }
}


/*
 * Retourne la longueur du header en bytes si le champs pkt->length
 * a une valeur valide pour un champs de type varuint (i.e. pkt->length < 0x8000).
 * Retourne -1 sinon
 * @pre: pkt contient une adresse valide (!= NULL)
 */
ssize_t predict_header_length(const pkt_t *pkt)
{
    if(pkt->length < 32768)
    {
        if(pkt->l == 0)
        {
            return((2+1+5+1+7+8+4+32)/8);
        }
        else
        {
            return((2+1+5+1+15+8+4+32)/8);
        }
    }
    return -1;
}

