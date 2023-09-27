import json
import os
import tempfile

from donut_decryptor.donut_decryptor import DonutDecryptor

from strelka import strelka


class ScanDonut(strelka.Scanner):
    """Extracts configs and modules from donut payloads"""

    def scan(self, data, file, options, expire_at):
        tmp_directory = options.get("tmp_directory", "/tmp/")

        with tempfile.NamedTemporaryFile(dir=tmp_directory, mode="wb") as tmp_data:
            tmp_data.write(data)
            tmp_data.flush()
            tmp_data.seek(0)

            try:
                donuts = DonutDecryptor.find_donuts(tmp_data.name)
            except Exception:
                # Set output flag on error
                self.flags.append("donut_decrypt_find_exception")

            self.event["total"] = {"donuts": len(donuts), "files": 0}

            self.event["donuts"] = []

            for donut in donuts:
                donut_data = {}
                donut_data["instance_version"] = donut.instance_version
                donut_data["loader_version"] = donut.loader_version
                donut_data["offset_loader_start"] = donut.offset_loader_start
                donut_data["offsets"] = {}
                donut_data["offsets"]["size_instance"] = donut.offsets.get(
                    "size_instance"
                )
                donut_data["offsets"]["encryption_start"] = donut.offsets.get(
                    "encryption_start"
                )

                self.event["donuts"].append(donut_data)

                try:
                    with tempfile.TemporaryDirectory() as tmpdirname:
                        donut.parse(tmpdirname)

                        # Retrieve module file
                        with open(
                            os.path.join(
                                tmpdirname, f"mod_{os.path.basename(tmp_data.name)}"
                            ),
                            "rb",
                        ) as mod_file:
                            # Send extracted file back to Strelka
                            self.emit_file(mod_file.read())
                            self.event["total"]["files"] += 1

                        # Retrieve instance metadata file
                        with open(
                            os.path.join(
                                tmpdirname, f"inst_{os.path.basename(tmp_data.name)}"
                            ),
                            "rb",
                        ) as inst_file:
                            inst_json = json.load(inst_file)

                            # Remove unneeded File key
                            inst_json.pop("File", None)

                            def change_dict_key(
                                d, old_key, new_key, default_value=None
                            ):
                                d[new_key] = d.pop(old_key, default_value)

                            # Reformat the dictionary keys to be consistent
                            for key in inst_json:
                                change_dict_key(
                                    inst_json, key, key.lower().replace(" ", "_")
                                )

                            # Update the current donut output
                            self.event["donuts"][len(self.event["donuts"]) - 1].update(
                                inst_json
                            )

                except Exception:
                    # Set output flag on error
                    self.flags.append("donut_decrypt_parse_exception")
