import bs4

from strelka import strelka


class ScanHtml(strelka.Scanner):
    """Collects metadata and extracts embedded scripts from HTML files.

    Options:
        parser: Sets the HTML parser used during scanning.
            Defaults to 'html.parser'.
    """
    def scan(self, data, file, options, expire_at):
        parser = options.get('parser', 'html.parser')

        self.event['total'] = {
            'scripts': 0,
            'forms': 0,
            'inputs': 0,
            'frames': 0,
            'extracted': 0,
        }

        try:
            soup = bs4.BeautifulSoup(data, parser)

            if soup.title:
                self.event['title'] = strelka.normalize_whitespace(soup.title.text)

            hyperlinks = []
            hyperlinks.extend(soup.find_all('a', href=True))
            hyperlinks.extend(soup.find_all('img', src=True))
            self.event.setdefault('hyperlinks', [])
            for hyperlink in hyperlinks:
                link = hyperlink.get('href') or hyperlink.get('src')
                if link not in self.event['hyperlinks']:
                    self.event['hyperlinks'].append(link)

            forms = soup.find_all('form')
            self.event['total']['forms'] = len(forms)
            self.event.setdefault('forms', [])
            for form in forms:
                form_entry = {
                    'action': form.get('action'),
                    'method': form.get('method'),
                }
                if form_entry not in self.event['forms']:
                    self.event['forms'].append(form_entry)

            frames = []
            frames.extend(soup.find_all('frame'))
            frames.extend(soup.find_all('iframe'))
            self.event['total']['frames'] = len(frames)
            self.event.setdefault('frames', [])
            for frame in frames:
                frame_entry = {
                    'src': frame.get('src'),
                    'name': frame.get('name'),
                    'height': frame.get('height'),
                    'width': frame.get('width'),
                    'border': frame.get('border'),
                    'id': frame.get('id'),
                    'style': frame.get('style'),
                }
                if frame_entry not in self.event['frames']:
                    self.event['frames'].append(frame_entry)

            inputs = soup.find_all('input')
            self.event['total']['inputs'] = len(inputs)
            self.event.setdefault('inputs', [])
            for html_input in inputs:
                input_entry = {
                    'type': html_input.get('type'),
                    'name': html_input.get('name'),
                    'value': html_input.get('value'),
                }
                if input_entry not in self.event['inputs']:
                    self.event['inputs'].append(input_entry)

            scripts = soup.find_all('script')
            self.event['total']['scripts'] = len(scripts)
            self.event.setdefault('scripts', [])
            for (index, script) in enumerate(scripts):
                script_flavors = [
                    script.get('language', '').lower(),
                    script.get('type', '').lower(),
                ]
                script_entry = {
                    'src': script.get('src'),
                    'language': script.get('language'),
                    'type': script.get('type'),
                }
                if script_entry not in self.event['scripts']:
                    self.event['scripts'].append(script_entry)

                if script.text:
                    extract_file = strelka.File(
                        name=f'script_{index}',
                        source=self.name,
                    )
                    extract_file.add_flavors({'external': script_flavors})

                    for c in strelka.chunk_string(script.text):
                        self.upload_to_coordinator(
                            extract_file.pointer,
                            c,
                            expire_at,
                        )

                    self.files.append(extract_file)
                    self.event['total']['extracted'] += 1

            spans = soup.find_all('span')
            self.event['total']['spans'] = len(spans)
            self.event.setdefault('spans', [])
            for span in spans:
                span_entry = {
                    'class': span.get('class'),
                    'style': span.get('style'),
                }
                if span_entry not in self.event['spans']:
                    self.event['spans'].append(span_entry)

        except TypeError:
            self.flags.append('type_error')
