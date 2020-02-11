import os
import re
import glob
import uuid
import hashlib

import requests

from lxml import etree


class Schema:

    def __init__(self, schemafile):
        self._schema_space = "{http://www.w3.org/2001/XMLSchema}"
        parser = etree.XMLParser(remove_comments=True)
        self.root = etree.parse(schemafile, parser=parser)

    def findall(self, path):
        return self.root.findall(path.replace("xs:", self._schema_space))

    def find(self, path):
        return self.root.find(path.replace("xs:", self._schema_space))

    @staticmethod
    def names_of(nodes: list) -> list:
        return [node.get("name") for node in nodes]

    def get_types(self, t_name: str) -> list:
        return self.names_of(self.findall(t_name))

    def get_simple_types(self) -> list:
        return self.get_types("xs:simpleType")

    def get_complex_types(self) -> list:
        return self.get_types("xs:complexType")

    def get_elements_of_attribute(self, attribute: str) -> list:
        return self.names_of(self.findall(f".//xs:element/xs:complexType/xs:{attribute}/../.."))

    def get_element_attributes(self, name: str) -> dict or None:

        node = self.find(f".//xs:element[@name='{name}']")
        if node is None:
            node = self.find(f".//xs:complexType[@name='{name}']")

        if node is None:
            return None
        else:
            return node.attrib

    def get_all_tags(self) -> list:

        return [{"tag": child.tag, "text": child.text, "attrib": child.attrib} for child in self.root.iter()]

    def get_element_full(self, name: str) -> list or None:

        node = self.find(f".//xs:element[@name='{name}']")
        if node is None:
            node = self.find(f".//xs:complexType[@name='{name}']")

        if node is None:
            return None
        else:
            return [{"tag": child.tag, "text": child.text, "attrib": child.attrib} for child in node.iter()]

    def get_command_args(self, name: str) -> dict or None:
        # Cheating slightly as this method knows a little about the BW OCI protocol but this is the most useful
        # place to have it v0v
        node = self.find(f".//xs:element[@name='{name}']")
        if node is None:
            node = self.find(f".//xs:complexType[@name='{name}']")

        if node is None:
            return None
        else:
            detail = self.get_element_full(name)
            args = [x['attrib'] for x in detail if x['tag'] == f'{self._schema_space}element']
            line = {"request": name, "args": args}

            return line


class BroadworksOCI:

    class XMLNamespaces:
        ns2 = "C"
        xsd = "http://www.w3.org/2001/XMLSchema"
        xsi = "http://www.w3.org/2001/XMLSchema-instance"
        soapenv = "http://schemas.xmlsoap.org/soap/envelope/"
        soapenc = "http://schemas.xmlsoap.org/soap/encoding/"
        NSMAP_NS2 = {"ns2": ns2}
        NSMAP_SOAPENV = {"soapenv": soapenv}
        NSMAP_SOAPENC = {"soapenc": soapenc}
        NSMAP_ENVELOPE = {"soapenv": soapenv, "xsd": xsd, "xsi": xsi}
        NSMAP_XSD = {"xsd": xsd}
        NSMAP_XSI = {"xsi": xsi}

    @staticmethod
    def load_schema(working_dir: str) -> list:

        schema_name = re.compile(r"OCISchema(\w+)\.xsd")
        output_list = []

        xsd_list = [filename for filename in glob.glob(os.path.join(working_dir, "**", "*.xsd"), recursive=True)]

        for xsd in xsd_list:
            is_xsd = schema_name.search(xsd)
            if is_xsd:
                output_list.append({"name": is_xsd[1], "schema": Schema(xsd)})

        return output_list

    def __init__(self, schema_dir):

        self.schema = self.load_schema(schema_dir)

    def list_all_commands(self):

        for schema in self.schema:
            print(schema['schema'].get_complex_types())

    def find_command(self, command_name: str) -> dict:

        for schema in self.schema:

            if command_name in schema['schema'].get_complex_types():

                return {"schema": schema['name'], "command": schema['schema'].get_command_args(command_name)}

    @staticmethod
    def generic_table_decoder(response: etree.ElementTree) -> list:

        output = []

        try:
            _col_headings = [k.text for k in response.findall(".//colHeading")]
            _rows = response.findall(".//row")

            for row in _rows:

                _values = [child.text for child in row]
                _zipped = zip(_col_headings, _values)
                output.append(dict(_zipped))

        except AttributeError:
            print(f"Failed to enumerate rows from the response {response}")

        return output

    def build_envelope(self, payload: str) -> str:
        """Builds the outer SOAP envelope for a BW OCI request.
        Also inserts the inner XML message into its proper place and
        returns the whole thing serialised to a string that can be directly attached to
        an HTTP request and sent to BW"""

        root = etree.Element(etree.QName(self.XMLNamespaces.soapenv, "Envelope"),
                             nsmap=self.XMLNamespaces.NSMAP_ENVELOPE)
        body = etree.SubElement(root, etree.QName(self.XMLNamespaces.soapenv, "Body"))
        process = etree.SubElement(body,
                                   "processOCIMessage",
                                   nsmap=self.XMLNamespaces.NSMAP_SOAPENV,
                                   )
        arg0 = etree.SubElement(process, "arg0", nsmap=self.XMLNamespaces.NSMAP_SOAPENC)

        process.attrib[etree.QName(self.XMLNamespaces.soapenv,
                                   "encodingStyle")] = "http://schemas.xmlsoap.org/soap/encoding/"
        arg0.attrib[etree.QName(self.XMLNamespaces.xsi, "type")] = "soapenc:string"
        arg0.text = payload

        tree = etree.ElementTree(root)

        # tostring() actually returns bytes despite what the docco says...
        bstring = etree.tostring(tree, encoding="utf-8", xml_declaration=True)

        # ...so make it an encoded string instead
        return "".join(chr(x) for x in bstring)

    def build_inner(self, command_details: dict, session_id: str) -> str:
        """Expects to receive a Dict of the format:

            {"command": <command name>, "arg_list": [{"<argument1 name>": <argument1 value>},
                                                     {"<argument2 name>": <argument2 value>}]}

        Returns the command tree serialised as a byte string ready to pass to build_envelope()"""

        root = etree.Element(etree.QName(self.XMLNamespaces.ns2, "BroadsoftDocument"),
                             nsmap=self.XMLNamespaces.NSMAP_NS2)
        sid = etree.SubElement(root, "sessionId")
        command = etree.SubElement(root, "command", nsmap=self.XMLNamespaces.NSMAP_XSI)

        root.attrib["protocol"] = "OCI"
        command.attrib[etree.QName(self.XMLNamespaces.xsi, "type")] = command_details["command"]

        sid.text = session_id

        if len(command_details["arg_list"]) != 0:
            try:
                for arg in command_details["arg_list"]:
                    for arg_name, arg_value in arg.items():
                        sub_elem = etree.SubElement(command, arg_name)
                        sub_elem.text = arg_value
            except KeyError:
                print("Broken Command Details Received")
        else:
            command.text = ""

        tree = etree.ElementTree(root)

        return etree.tostring(tree, encoding="utf-8", xml_declaration=True, standalone=True)

    def build_inner_xml(self, command_str: str, session_id: str) -> str:
        """Expects to receive a preformatted XML String for a </command>

        Returns the command tree serialised as a byte string ready to pass to build_envelope()"""

        root = etree.Element(etree.QName(self.XMLNamespaces.ns2, "BroadsoftDocument"),
                             nsmap=self.XMLNamespaces.NSMAP_NS2)
        sid = etree.SubElement(root, "sessionId")
        command = etree.fromstring(str(command_str))
        root.append(command)

        root.attrib["protocol"] = "OCI"

        sid.text = session_id

        tree = etree.ElementTree(root)

        print(etree.tostring(root, pretty_print=True))

        return etree.tostring(tree, encoding="utf-8", xml_declaration=True, standalone=True)

    @staticmethod
    def remove_envelope(enveloped: bytes) -> bytes or bool:

        root = etree.fromstring(enveloped)

        for element in root.iter():
            if element.tag == "{urn:com:broadsoft:webservice}processOCIMessageReturn":

                return element.text.encode()

        return False

    def process_response(self, inner: bytes) -> dict or bool:

        _output = {}
        _excludes = ["colHeading", "col", "row", "command", "{C}BroadsoftDocument", "sessionId"]

        oci_response = etree.fromstring(inner)

        command = oci_response.find("command")

        # No command element - whole thing is broken
        if command is None:

            return False

        # Find an OCI error response and return the summary and details for debugging
        if command.attrib["{http://www.w3.org/2001/XMLSchema-instance}type"] == "Error":
            summary = oci_response.find("summaryEnglish")
            detail = oci_response.find("detail")

            return {"type": "Error", "summary": summary, "detail": detail}

        # Otherwise, iterate through the elements...
        for element in oci_response.iter():
            # ...if it's a table, special processing
            if re.search(r"Table", element.tag):
                _table = self.generic_table_decoder(element)
                _output[element.tag] = _table
            else:
                if element.tag not in _excludes:
                    _output[element.tag] = element.text

        return _output


class OciClient:

    def __init__(self, url: str, user: str, plain_password: str):

        self.url = url
        self.user = user
        self.plain_password = plain_password

        # self.oci = BroadworksOCI("/Users/ben/PycharmProjects/oci_client_v2/schema")
        self.oci = BroadworksOCI(os.environ["SCHEMA_DIR"])

        self.headers = {'SOAPAction': '', 'Cookie': ''}
        self.signed_password = ''
        self.session_id = uuid.uuid4()

    # Generics and Authentication, login, logoff commands etc
    @staticmethod
    def generate_signed_password(plain_password: str, nonce: str) -> str:
        p = hashlib.sha1()
        p.update(bytes(plain_password, encoding="ascii"))
        s1 = p.hexdigest()
        s2 = f"{nonce}:{s1}"
        s3 = hashlib.md5()
        s3.update(bytes(s2, encoding="ascii"))

        return s3.hexdigest()

    def get_nonce(self, user: str) -> str or bool:
        # Send our Auth Request the XSI to get our Nonce
        r = self.send_oci("AuthenticationRequest", [{"userId": user}])

        body = self.process_oci_response(r)

        return body["nonce"] if "nonce" in body.keys() else False

    def login(self, user: str, signed_password: str) -> bool:
        # Try and log into the XSP with the signed password from generate_signed_password()
        li = self.send_oci("LoginRequest14sp4", [{"userId": user},
                                                 {"signedPassword": signed_password}])

        if li is not False:
            return True
        else:
            print("Failed to log in to the XSP")
            return False

    def logout(self, user: str) -> bool:
        # Clean up XSP connection=
        print("Sending Logout Request to the XSP")
        lo = self.send_oci("LogoutRequest", [{"userId": user}])

        if lo is not False:
            return True
        else:
            print(f"Failed to log out of the XSP")
            return lo

    def create(self):
        # Wrapper for the whole login/authenticate procedure
        n = self.get_nonce(self.user)
        self.signed_password = self.generate_signed_password(self.plain_password, n)
        self.login(self.user, self.signed_password)

    def close(self):
        # Wrapper for the whole logout procedure
        self.logout(self.user)

    def send_oci(self, command: str, arg_list: list) -> str or bool:
        # Generic function for preparing and sending an OCI request to BW
        body = self.oci.build_envelope(
            self.oci.build_inner(
                {"command": command, "arg_list": arg_list},
                str(self.session_id)
            )
        )

        req = requests.post(f"{self.url}",
                            data=body,
                            headers=self.headers)

        if req.status_code == 200:
            # Special treatment for an Auth Request
            if command == "AuthenticationRequest":
                # Extract and set the JSESSIONID
                jsessionid = req.headers['set-cookie']
                jsessionid = jsessionid.split(';')[0]
                self.headers['Cookie'] = jsessionid

            return req.text

        else:
            return False

    def send_oci_xml(self, command: str) -> str or bool:
        # Generic function for submitting a pre-formatted <command> OCI request to BW
        body = self.oci.build_envelope(
            self.oci.build_inner_xml(
                command,
                str(self.session_id)
            )
        )

        req = requests.post(f"{self.url}",
                            data=body,
                            headers=self.headers)

        if req.status_code == 200:
            # Special treatment for an Auth Request
            if command == "AuthenticationRequest":
                # Extract and set the JSESSIONID
                jsessionid = req.headers['set-cookie']
                jsessionid = jsessionid.split(';')[0]
                self.headers['Cookie'] = jsessionid

            return req.text

        else:
            return False

    def process_oci_response(self, response: str) -> dict or bool:

        inner = self.oci.remove_envelope(response.encode())
        cleaned = self.oci.process_response(inner)

        return cleaned
