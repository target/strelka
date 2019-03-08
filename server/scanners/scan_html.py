import bs4

from server import lib


class ScanHtml(lib.StrelkaScanner):
    """Collects metadata and extracts embedded scripts from HTML files.

    Options:
        parser: Sets the HTML parser used during scanning.
            Defaults to 'html.parser'.
    """
    def scan(self, file_object, options):
        parser = options.get('parser', 'html.parser')

        self.metadata['total'] = {'scripts': 0, 'forms': 0, 'inputs': 0,
                                  'frames': 0, 'extracted': 0}

        try:
            soup = bs4.BeautifulSoup(file_object.data, parser)

            if soup.title:
                normalized_title = lib.normalize_whitespace(soup.title.text)
                self.metadata['title'] = normalized_title

            hyperlinks = []
            hyperlinks.extend(soup.find_all('a', href=True))
            hyperlinks.extend(soup.find_all('img', src=True))
            self.metadata.setdefault('hyperlinks', [])
            for hyperlink in hyperlinks:
                link = hyperlink.get('href') or hyperlink.get('src')
                if link is not None and link not in self.metadata['hyperlinks']:
                    self.metadata['hyperlinks'].append(link)

            forms = soup.find_all('form')
            self.metadata['total']['forms'] = len(forms)
            self.metadata.setdefault('forms', [])
            for form in forms:
                form_entry = {}
                form_action = form.get('action')
                if form_action is not None:
                    form_entry['action'] = form_action
                form_method = form.get('method')
                if form_method is not None:
                    form_entry['method'] = form_method
                if form_entry and form_entry not in self.metadata['forms']:
                    self.metadata['forms'].append(form_entry)

            frames = []
            frames.extend(soup.find_all('frame'))
            frames.extend(soup.find_all('iframe'))
            self.metadata['total']['frames'] = len(frames)
            self.metadata.setdefault('frames', [])
            for frame in frames:
                frame_entry = {}
                frame_src = frame.get('src')
                if frame_src is not None:
                    frame_entry['src'] = frame_src
                frame_name = frame.get('name')
                if frame_name is not None:
                    frame_entry['name'] = frame_name
                frame_height = frame.get('height')
                if frame_height is not None:
                    frame_entry['height'] = frame_height
                frame_width = frame.get('width')
                if frame_width is not None:
                    frame_entry['width'] = frame_width
                frame_border = frame.get('border')
                if frame_border is not None:
                    frame_entry['border'] = frame_border
                frame_id = frame.get('id')
                if frame_id is not None:
                    frame_entry['id'] = frame_id
                frame_style = frame.get('style')
                if frame_style is not None:
                    frame_entry['style'] = frame_style
                if frame_entry and frame_entry not in self.metadata['frames']:
                    self.metadata['frames'].append(frame_entry)

            inputs = soup.find_all('input')
            self.metadata['total']['inputs'] = len(inputs)
            self.metadata.setdefault('inputs', [])
            for input in inputs:
                input_entry = {}
                input_type = input.get('type')
                if input_type is not None:
                    input_entry['type'] = input_type
                input_name = input.get('name')
                if input_name is not None:
                    input_entry['name'] = input_name
                input_value = input.get('value')
                if input_value is not None:
                    input_entry['value'] = input_value
                if input_entry and input_entry not in self.metadata['inputs']:
                    self.metadata['inputs'].append(input_entry)

            scripts = soup.find_all('script')
            self.metadata['total']['scripts'] = len(scripts)
            self.metadata.setdefault('scripts', [])
            for (index, script) in enumerate(scripts):
                script_flavors = []
                script_entry = {}
                script_src = script.get('src')
                if script_src is not None:
                    script_entry['src'] = script_src
                script_language = script.get('language')
                if script_language is not None:
                    script_entry['language'] = script_language
                    script_flavors.append(script_language.lower())
                script_type = script.get('type')
                if script_type is not None:
                    script_entry['type'] = script_type
                    script_flavors.append(script_type.lower())
                if script_entry and script_entry not in self.metadata['scripts']:
                    self.metadata['scripts'].append(script_entry)

                if script.text:
                    child_filename = f'{self.scanner_name}::script_{index}'
                    child_fo = lib.StrelkaFile(data=script.text,
                                               filename=child_filename,
                                               depth=file_object.depth + 1,
                                               parent_uid=file_object.uid,
                                               root_uid=file_object.root_uid,
                                               parent_hash=file_object.hash,
                                               root_hash=file_object.root_hash,
                                               source=self.scanner_name)
                    child_fo.add_ext_flavors(script_flavors)
                    self.children.append(child_fo)
                    self.metadata['total']['extracted'] += 1

            spans = soup.find_all('span')
            self.metadata['total']['spans'] = len(spans)
            self.metadata.setdefault('spans', [])
            for span in spans:
                span_entry = {}
                span_class = span.get('class')
                if span_class is not None:
                    span_entry['class'] = span_class
                span_style = span.get('style')
                if span_style is not None:
                    span_entry['style'] = span_style
                if span_entry and span_entry not in self.metadata['spans']:
                    self.metadata['spans'].append(span_entry)

        except TypeError:
            file_object.flags.append(f'{self.scanner_name}::type_error')
