from typing import List


class ProtobufScanner:
    """
    Best-effort scanner for schema-unknown protobuf messages.

    This does not attempt to reconstruct the original .proto schema.

    Instead, it:
        1. Removes the standard gRPC message envelope.
        2. Parses protobuf wire fields.
        3. Extracts length-delimited UTF-8 strings.

    The purpose is privacy-data discovery, not complete protobuf decoding.
    """

    @staticmethod
    def _read_varint(
        data: bytes,
        offset: int
    ):

        """
        Read a protobuf varint.

        Returns:
            (value, new_offset)
        """

        value = 0
        shift = 0

        while offset < len(data):

            byte = data[offset]

            offset += 1

            value |= (
                byte & 0x7F
            ) << shift

            # End of varint.
            if not (
                byte & 0x80
            ):

                return value, offset

            shift += 7

            # Protect against malformed data.
            if shift >= 64:

                return None, offset

        return None, offset

    @staticmethod
    def _decode_grpc_frame(
        body: bytes
    ) -> bytes:

        """
        Remove the standard 5-byte gRPC message envelope.

        gRPC message format:

            1 byte  -> compression flag
            4 bytes -> message length
            N bytes -> protobuf message
        """

        if len(body) < 5:

            return body

        message_length = int.from_bytes(
            body[1:5],
            byteorder="big"
        )

        remaining = len(body) - 5

        # Normal complete gRPC frame.
        if message_length <= remaining:

            return body[
                5:
                5 + message_length
            ]

        # Incomplete or malformed frame.
        return body

    @classmethod
    def extract_strings(
        cls,
        body: bytes
    ) -> List[str]:

        """
        Extract length-delimited UTF-8 strings from
        a schema-unknown protobuf message.

        Supported protobuf wire types:

            0 = varint
            1 = 64-bit
            2 = length-delimited
            5 = 32-bit

        Only wire type 2 is returned as text.
        """

        if not body:

            return []

        data = cls._decode_grpc_frame(
            body
        )

        strings = []

        offset = 0

        while offset < len(data):

            # --------------------------------------
            # Read field key
            # --------------------------------------

            field_key, offset = (
                cls._read_varint(
                    data,
                    offset
                )
            )

            if field_key is None:

                break

            wire_type = (
                field_key & 0x07
            )

            # --------------------------------------
            # Wire type 0: varint
            # --------------------------------------

            if wire_type == 0:

                _, offset = (
                    cls._read_varint(
                        data,
                        offset
                    )
                )

                continue

            # --------------------------------------
            # Wire type 1: 64-bit
            # --------------------------------------

            if wire_type == 1:

                if offset + 8 > len(data):

                    break

                offset += 8

                continue

            # --------------------------------------
            # Wire type 2:
            # length-delimited
            # --------------------------------------

            if wire_type == 2:

                length, offset = (
                    cls._read_varint(
                        data,
                        offset
                    )
                )

                if length is None:

                    break

                end = offset + length

                if end > len(data):

                    break

                value = data[
                    offset:end
                ]

                try:

                    text = value.decode(
                        "utf-8"
                    ).strip()

                    if text:

                        strings.append(
                            text
                        )

                except UnicodeDecodeError:

                    # Binary field, not a UTF-8 string.
                    pass

                offset = end

                continue

            # --------------------------------------
            # Wire type 5: 32-bit
            # --------------------------------------

            if wire_type == 5:

                if offset + 4 > len(data):

                    break

                offset += 4

                continue

            # --------------------------------------
            # Unsupported / invalid wire type
            # --------------------------------------

            break

        return strings