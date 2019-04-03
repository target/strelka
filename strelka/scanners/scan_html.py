import bs4

from strelka import core
from strelka.scanners import util


class ScanHtml(core.StrelkaScanner):
    """Collects metadata and extracts embedded scripts from HTML files.

    Options:
        parser: Sets the HTML parser used during scanning.
            Defaults to 'html.parser'.
    """
    def scan(self, st_file, options):
        parser = options.get('parser', 'html.parser')

        self.metadata['total'] = {
            'scripts': 0,
            'forms': 0,
            'inputs': 0,
            'frames': 0,
            'extracted': 0,
        }

        try:
            soup = bs4.BeautifulSoup(self.data, parser)

            if soup.title:
                self.metadata['title'] = util.normalize_whitespace(soup.title.text)

            hyperlinks = []
            hyperlinks.extend(soup.find_all('a', href=True))
            hyperlinks.extend(soup.find_all('img', src=True))
            self.metadata.setdefault('hyperlinks', [])
            for hyperlink in hyperlinks:
                link = hyperlink.get('href') or hyperlink.get('src')
                if link not in self.metadata['hyperlinks']:
                    self.metadata['hyperlinks'].append(link)

            forms = soup.find_all('form')
            self.metadata['total']['forms'] = len(forms)
            self.metadata.setdefault('forms', [])
            for form in forms:
                form_entry = {
                    'action': form.get('action'),
                    'method': form.get('method'),
                }
                if form_entry not in self.metadata['forms']:
                    self.metadata['forms'].append(form_entry)

            frames = []
            frames.extend(soup.find_all('frame'))
            frames.extend(soup.find_all('iframe'))
            self.metadata['total']['frames'] = len(frames)
            self.metadata.setdefault('frames', [])
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
                if frame_entry not in self.metadata['frames']:
                    self.metadata['frames'].append(frame_entry)

            inputs = soup.find_all('input')
            self.metadata['total']['inputs'] = len(inputs)
            self.metadata.setdefault('inputs', [])
            for input in inputs:
                input_entry = {
                    'type': input.get('type'),
                    'name': input.get('name'),
                    'value': input.get('value'),
                }
                if input_entry not in self.metadata['inputs']:
                    self.metadata['inputs'].append(input_entry)

            scripts = soup.find_all('script')
            self.metadata['total']['scripts'] = len(scripts)
            self.metadata.setdefault('scripts', [])
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
                if script_entry not in self.metadata['scripts']:
                    self.metadata['scripts'].append(script_entry)

                if script.text:
                    ex_file = core.StrelkaFile(
                        name=f'script_{index}',
                        source=self.name,
                    )
                    ex_file.add_flavors({'external': script_flavors})
                    for c in util.chunk_string(script.text):
                        p = self.fk.pipeline()
                        p.rpush(ex_file.uid, c)
                        p.expire(ex_file.uid, self.expire)
                        p.execute()
                    self.files.append(ex_file)

                    self.metadata['total']['extracted'] += 1

            spans = soup.find_all('span')
            self.metadata['total']['spans'] = len(spans)
            self.metadata.setdefault('spans', [])
            for span in spans:
                span_entry = {
                    'class': span.get('class'),
                    'style': span.get('style'),
                }
                if span_entry not in self.metadata['spans']:
                    self.metadata['spans'].append(span_entry)

        except TypeError:
            self.flags.add('type_error')
