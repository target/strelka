from lxml import etree

from server import lib


class ScanXml(lib.StrelkaScanner):
    """Collects metadata and extracts embedded files from XML files.

    Options:
        extract_tags: List of XML tags that will have their text extracted
            as child files.
            Defaults to empty list.
        metadata_tags: List of XML tags that will have their text logged
            as metadata.
            Defaults to empty list.
    """
    def scan(self, file_object, options):
        xml_args = {}
        xml_args['extract_tags'] = options.get('extract_tags', [])
        xml_args['metadata_tags'] = options.get('metadata_tags', [])

        self.metadata.setdefault('tags', [])
        self.metadata.setdefault('tagData', [])
        self.metadata.setdefault('namespaces', [])
        self.metadata['total'] = {'tags': 0, 'extracted': 0}

        xml = None
        try:
            xml_buffer = file_object.data
            if xml_buffer.startswith(b'<?XML'):
                xml_buffer = b'<?xml' + xml_buffer[5:]
            xml = etree.fromstring(xml_buffer)
            docinfo = xml.getroottree().docinfo
            if docinfo.doctype:
                self.metadata['docType'] = docinfo.doctype
            if docinfo.xml_version:
                self.metadata['version'] = docinfo.xml_version

        except etree.XMLSyntaxError:
            file_object.flags.append(f'{self.scanner_name}::syntax_error')

        if xml is not None:
            self._recurse_node(self, xml, xml_args, file_object)

    @staticmethod
    def _recurse_node(self, node, xml_args, file_object):
        """Recursively parses XML file.

        The XML file is recursively parsed down every node tree.

        Args:
            node: node to be recursively parsed.
            xml_args: options set by the scanner that affect XMl parsing.
            file_object: file object being scanned.
        """
        if node is not None:
            if hasattr(node.tag, '__getitem__'):
                if node.tag.startswith('{'):
                    namespace, separator, tag = node.tag[1:].partition('}')
                else:
                    namespace = None
                    tag = node.tag

                self.metadata['total']['tags'] += 1
                if (namespace is not None and
                    namespace not in self.metadata['namespaces']):
                    self.metadata['namespaces'].append(namespace)
                if tag not in self.metadata['tags']:
                    self.metadata['tags'].append(tag)

                text = node.attrib.get('name', node.text)
                if text is not None:
                    if (xml_args['metadata_tags'] and
                        tag in xml_args['metadata_tags']):
                        tag_data = {'tag': tag, 'text': text.strip()}
                        if tag_data not in self.metadata['tagData']:
                            self.metadata['tagData'].append(tag_data)
                    elif (xml_args['extract_tags'] and
                          tag in xml_args['extract_tags']):
                        child_filename = f'{self.scanner_name}::{tag}'
                        child_fo = lib.StrelkaFile(data=text,
                                                   filename=child_filename,
                                                   depth=file_object.depth + 1,
                                                   parent_uid=file_object.uid,
                                                   root_uid=file_object.root_uid,
                                                   parent_hash=file_object.hash,
                                                   root_hash=file_object.root_hash,
                                                   source=self.scanner_name)
                        self.children.append(child_fo)
                        self.metadata['total']['extracted'] += 1

            for child in node.getchildren():
                self._recurse_node(self, child, xml_args, file_object)

        return
