import difflib
from pathlib import Path
from unittest import TestCase, mock

from strelka.scanners.scan_ocr import ScanOcr as ScanUnderTest
from strelka.tests import run_test_scan


def test_scan_ocr_jpg(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "string_text": b"Lorem Ipsum Lorem ipsum dolor sit amet, consectetur adipisci"
        b"ng elit. Cras lobortis sem dui. Morbi at magna quis ligula f"
        b"aucibusconsectetur feugiat at purus. Sed nec lorem nibh. Nam"
        b" vel libero odio. Vivamus tempus non enim egestas pretium.Ve"
        b"stibulum turpis arcu, maximus nec libero quis, imperdiet sus"
        b"cipit purus. Vestibulum blandit quis lacus nonsollicitudin. "
        b"Nullam non convallis dui, et aliquet risus. Sed accumsan ull"
        b"amcorper vehicula. Proin non urna facilisis,condimentum eros"
        b" quis, suscipit purus. Morbi euismod imperdiet neque ferment"
        b"um dictum. Integer aliquam, erat sitamet fringilla tempus, m"
        b"auris ligula blandit sapien, et varius sem mauris eu diam. S"
        b"ed fringilla neque est, in laoreetfelis tristique in. Donec "
        b"luctus velit a posuere posuere. Suspendisse sodales pellente"
        b"sque quam.",
        "text": [
            b"Lorem",
            b"Ipsum",
            b"Lorem",
            b"ipsum",
            b"dolor",
            b"sit",
            b"amet,",
            b"consectetur",
            b"adipiscing",
            b"elit.",
            b"Cras",
            b"lobortis",
            b"sem",
            b"dui.",
            b"Morbi",
            b"at",
            b"magna",
            b"quis",
            b"ligula",
            b"faucibus",
            b"consectetur",
            b"feugiat",
            b"at",
            b"purus.",
            b"Sed",
            b"nec",
            b"lorem",
            b"nibh.",
            b"Nam",
            b"vel",
            b"libero",
            b"odio.",
            b"Vivamus",
            b"tempus",
            b"non",
            b"enim",
            b"egestas",
            b"pretium.",
            b"Vestibulum",
            b"turpis",
            b"arcu,",
            b"maximus",
            b"nec",
            b"libero",
            b"quis,",
            b"imperdiet",
            b"suscipit",
            b"purus.",
            b"Vestibulum",
            b"blandit",
            b"quis",
            b"lacus",
            b"non",
            b"sollicitudin.",
            b"Nullam",
            b"non",
            b"convallis",
            b"dui,",
            b"et",
            b"aliquet",
            b"risus.",
            b"Sed",
            b"accumsan",
            b"ullamcorper",
            b"vehicula.",
            b"Proin",
            b"non",
            b"urna",
            b"facilisis,",
            b"condimentum",
            b"eros",
            b"quis,",
            b"suscipit",
            b"purus.",
            b"Morbi",
            b"euismod",
            b"imperdiet",
            b"neque",
            b"fermentum",
            b"dictum.",
            b"Integer",
            b"aliquam,",
            b"erat",
            b"sit",
            b"amet",
            b"fringilla",
            b"tempus,",
            b"mauris",
            b"ligula",
            b"blandit",
            b"sapien,",
            b"et",
            b"varius",
            b"sem",
            b"mauris",
            b"eu",
            b"diam.",
            b"Sed",
            b"fringilla",
            b"neque",
            b"est,",
            b"in",
            b"laoreet",
            b"felis",
            b"tristique",
            b"in.",
            b"Donec",
            b"luctus",
            b"velit",
            b"a",
            b"posuere",
            b"posuere.",
            b"Suspendisse",
            b"sodales",
            b"pellentesque",
            b"quam.",
        ],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_text.jpg",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_ocr_png(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "string_text": b"Lorem Ipsum Lorem ipsum dolor sit amet, consectetur adipisci"
        b"ng elit. Cras lobortis sem dui. Morbi at magna quis ligula f"
        b"aucibusconsectetur feugiat at purus. Sed nec lorem nibh. Nam"
        b" vel libero odio. Vivamus tempus non enim egestas pretium.Ve"
        b"stibulum turpis arcu, maximus nec libero quis, imperdiet sus"
        b"cipit purus. Vestibulum blandit quis lacus nonsollicitudin. "
        b"Nullam non convallis dui, et aliquet risus. Sed accumsan ull"
        b"amcorper vehicula. Proin non urna facilisis,condimentum eros"
        b" quis, suscipit purus. Morbi euismod imperdiet neque ferment"
        b"um dictum. Integer aliquam, erat sitamet fringilla tempus, m"
        b"auris ligula blandit sapien, et varius sem mauris eu diam. S"
        b"ed fringilla neque est, in laoreetfelis tristique in. Donec "
        b"luctus velit a posuere posuere. Suspendisse sodales pellente"
        b"sque quam.",
        "text": [
            b"Lorem",
            b"Ipsum",
            b"Lorem",
            b"ipsum",
            b"dolor",
            b"sit",
            b"amet,",
            b"consectetur",
            b"adipiscing",
            b"elit.",
            b"Cras",
            b"lobortis",
            b"sem",
            b"dui.",
            b"Morbi",
            b"at",
            b"magna",
            b"quis",
            b"ligula",
            b"faucibus",
            b"consectetur",
            b"feugiat",
            b"at",
            b"purus.",
            b"Sed",
            b"nec",
            b"lorem",
            b"nibh.",
            b"Nam",
            b"vel",
            b"libero",
            b"odio.",
            b"Vivamus",
            b"tempus",
            b"non",
            b"enim",
            b"egestas",
            b"pretium.",
            b"Vestibulum",
            b"turpis",
            b"arcu,",
            b"maximus",
            b"nec",
            b"libero",
            b"quis,",
            b"imperdiet",
            b"suscipit",
            b"purus.",
            b"Vestibulum",
            b"blandit",
            b"quis",
            b"lacus",
            b"non",
            b"sollicitudin.",
            b"Nullam",
            b"non",
            b"convallis",
            b"dui,",
            b"et",
            b"aliquet",
            b"risus.",
            b"Sed",
            b"accumsan",
            b"ullamcorper",
            b"vehicula.",
            b"Proin",
            b"non",
            b"urna",
            b"facilisis,",
            b"condimentum",
            b"eros",
            b"quis,",
            b"suscipit",
            b"purus.",
            b"Morbi",
            b"euismod",
            b"imperdiet",
            b"neque",
            b"fermentum",
            b"dictum.",
            b"Integer",
            b"aliquam,",
            b"erat",
            b"sit",
            b"amet",
            b"fringilla",
            b"tempus,",
            b"mauris",
            b"ligula",
            b"blandit",
            b"sapien,",
            b"et",
            b"varius",
            b"sem",
            b"mauris",
            b"eu",
            b"diam.",
            b"Sed",
            b"fringilla",
            b"neque",
            b"est,",
            b"in",
            b"laoreet",
            b"felis",
            b"tristique",
            b"in.",
            b"Donec",
            b"luctus",
            b"velit",
            b"a",
            b"posuere",
            b"posuere.",
            b"Suspendisse",
            b"sodales",
            b"pellentesque",
            b"quam.",
        ],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_text.png",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_ocr_webp(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "string_text": b"Lorem Ipsum Lorem ipsum dolor sit amet, consectetur adipisci"
        b"ng elit. Cras lobortis sem dui. Morbi at magna quis ligula f"
        b"aucibusconsectetur feugiat at purus. Sed nec lorem nibh. Nam"
        b" vel libero odio. Vivamus tempus non enim egestas pretium.Ve"
        b"stibulum turpis arcu, maximus nec libero quis, imperdiet sus"
        b"cipit purus. Vestibulum blandit quis lacus nonsollicitudin. "
        b"Nullam non convallis dui, et aliquet risus. Sed accumsan ull"
        b"amcorper vehicula. Proin non urna facilisis,condimentum eros"
        b" quis, suscipit purus. Morbi euismod imperdiet neque ferment"
        b"um dictum. Integer aliquam, erat sitamet fringilla tempus, m"
        b"auris ligula blandit sapien, et varius sem mauris eu diam. S"
        b"ed fringilla neque est, in laoreetfelis tristique in. Donec "
        b"luctus velit a posuere posuere. Suspendisse sodales pellente"
        b"sque quam.",
        "text": [
            b"Lorem",
            b"Ipsum",
            b"Lorem",
            b"ipsum",
            b"dolor",
            b"sit",
            b"amet,",
            b"consectetur",
            b"adipiscing",
            b"elit.",
            b"Cras",
            b"lobortis",
            b"sem",
            b"dui.",
            b"Morbi",
            b"at",
            b"magna",
            b"quis",
            b"ligula",
            b"faucibus",
            b"consectetur",
            b"feugiat",
            b"at",
            b"purus.",
            b"Sed",
            b"nec",
            b"lorem",
            b"nibh.",
            b"Nam",
            b"vel",
            b"libero",
            b"odio.",
            b"Vivamus",
            b"tempus",
            b"non",
            b"enim",
            b"egestas",
            b"pretium.",
            b"Vestibulum",
            b"turpis",
            b"arcu,",
            b"maximus",
            b"nec",
            b"libero",
            b"quis,",
            b"imperdiet",
            b"suscipit",
            b"purus.",
            b"Vestibulum",
            b"blandit",
            b"quis",
            b"lacus",
            b"non",
            b"sollicitudin.",
            b"Nullam",
            b"non",
            b"convallis",
            b"dui,",
            b"et",
            b"aliquet",
            b"risus.",
            b"Sed",
            b"accumsan",
            b"ullamcorper",
            b"vehicula.",
            b"Proin",
            b"non",
            b"urna",
            b"facilisis,",
            b"condimentum",
            b"eros",
            b"quis,",
            b"suscipit",
            b"purus.",
            b"Morbi",
            b"euismod",
            b"imperdiet",
            b"neque",
            b"fermentum",
            b"dictum.",
            b"Integer",
            b"aliquam,",
            b"erat",
            b"sit",
            b"amet",
            b"fringilla",
            b"tempus,",
            b"mauris",
            b"ligula",
            b"blandit",
            b"sapien,",
            b"et",
            b"varius",
            b"sem",
            b"mauris",
            b"eu",
            b"diam.",
            b"Sed",
            b"fringilla",
            b"neque",
            b"est,",
            b"in",
            b"laoreet",
            b"felis",
            b"tristique",
            b"in.",
            b"Donec",
            b"luctus",
            b"velit",
            b"a",
            b"posuere",
            b"posuere.",
            b"Suspendisse",
            b"sodales",
            b"pellentesque",
            b"quam.",
        ],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_text.webp",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_ocr_gif(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "string_text": b"Lorem Ipsum Lorem ipsum dolor sit amet, consectetur adipisci"
        b"ng elit. Cras lobortis sem dui. Morbi at magna quis ligula f"
        b"aucibusconsectetur feugiat at purus. Sed nec lorem nibh. Nam"
        b" vel libero odio. Vivamus tempus non enim egestas pretium.Ve"
        b"stibulum turpis arcu, maximus nec libero quis, imperdiet sus"
        b"cipit purus. Vestibulum blandit quis lacus nonsollicitudin. "
        b"Nullam non convallis dui, et aliquet risus. Sed accumsan ull"
        b"amcorper vehicula. Proin non urna facilisis,condimentum eros"
        b" quis, suscipit purus. Morbi euismod imperdiet neque ferment"
        b"um dictum. Integer aliquam, erat sitamet fringilla tempus, m"
        b"auris ligula blandit sapien, et varius sem mauris eu diam. S"
        b"ed fringilla neque est, in laoreetfelis tristique in. Donec "
        b"luctus velit a posuere posuere. Suspendisse sodales pellente"
        b"sque quam.",
        "text": [
            b"Lorem",
            b"Ipsum",
            b"Lorem",
            b"ipsum",
            b"dolor",
            b"sit",
            b"amet,",
            b"consectetur",
            b"adipiscing",
            b"elit.",
            b"Cras",
            b"lobortis",
            b"sem",
            b"dui.",
            b"Morbi",
            b"at",
            b"magna",
            b"quis",
            b"ligula",
            b"faucibus",
            b"consectetur",
            b"feugiat",
            b"at",
            b"purus.",
            b"Sed",
            b"nec",
            b"lorem",
            b"nibh.",
            b"Nam",
            b"vel",
            b"libero",
            b"odio.",
            b"Vivamus",
            b"tempus",
            b"non",
            b"enim",
            b"egestas",
            b"pretium.",
            b"Vestibulum",
            b"turpis",
            b"arcu,",
            b"maximus",
            b"nec",
            b"libero",
            b"quis,",
            b"imperdiet",
            b"suscipit",
            b"purus.",
            b"Vestibulum",
            b"blandit",
            b"quis",
            b"lacus",
            b"non",
            b"sollicitudin.",
            b"Nullam",
            b"non",
            b"convallis",
            b"dui,",
            b"et",
            b"aliquet",
            b"risus.",
            b"Sed",
            b"accumsan",
            b"ullamcorper",
            b"vehicula.",
            b"Proin",
            b"non",
            b"urna",
            b"facilisis,",
            b"condimentum",
            b"eros",
            b"quis,",
            b"suscipit",
            b"purus.",
            b"Morbi",
            b"euismod",
            b"imperdiet",
            b"neque",
            b"fermentum",
            b"dictum.",
            b"Integer",
            b"aliquam,",
            b"erat",
            b"sit",
            b"amet",
            b"fringilla",
            b"tempus,",
            b"mauris",
            b"ligula",
            b"blandit",
            b"sapien,",
            b"et",
            b"varius",
            b"sem",
            b"mauris",
            b"eu",
            b"diam.",
            b"Sed",
            b"fringilla",
            b"neque",
            b"est,",
            b"in",
            b"laoreet",
            b"felis",
            b"tristique",
            b"in.",
            b"Donec",
            b"luctus",
            b"velit",
            b"a",
            b"posuere",
            b"posuere.",
            b"Suspendisse",
            b"sodales",
            b"pellentesque",
            b"quam.",
        ],
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_text.gif",
    )

    TestCase.maxDiff = None
    TestCase().assertDictEqual(test_scan_event, scanner_event)


def test_scan_ocr_keep_formatting(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "string_text": b"Lorem Ipsum\n\nLorem ipsum dolor sit amet, consectetur adipiscing elit. Cras lobortis sem dui. "
        b"Morbi at magna quis ligula faucibus\nconsectetur feugiat at purus. Sed nec lorem nibh. Nam vel "
        b"libero odio. Vivamus tempus non enim egestas pretium.\nVestibulum turpis arcu, maximus nec libero "
        b"quis, imperdiet suscipit purus. Vestibulum blandit quis lacus non\nsollicitudin. Nullam non "
        b"convallis dui, et aliquet risus. Sed accumsan ullamcorper vehicula. Proin non urna facilisis,"
        b"\ncondimentum eros quis, suscipit purus. Morbi euismod imperdiet neque fermentum dictum. Integer "
        b"aliquam, erat sit\namet fringilla tempus, mauris ligula blandit sapien, et varius sem mauris eu "
        b"diam. Sed fringilla neque est, in laoreet\nfelis tristique in. Donec luctus velit a posuere "
        b"posuere. Suspendisse sodales pellentesque quam.\n",
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_text.webp",
        options=({"split_words": False, "remove_formatting": False}),
    )

    TestCase.maxDiff = None

    # Output string formatting may result in slightly different results.
    # Comparing similarity to the 99% percentile is good enough.
    similarity = difflib.SequenceMatcher(
        None, test_scan_event["string_text"], scanner_event["string_text"]
    ).ratio()
    assert similarity > 0.99


def test_scan_ocr_thumbnail(mocker):
    """
    Pass: Sample event matches output of scanner.
    Failure: Unable to load file or sample event fails to match.
    """

    test_scan_event = {
        "elapsed": mock.ANY,
        "flags": [],
        "base64_thumbnail": "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",
        "string_text": b"Lorem Ipsum\n\nLorem ipsum dolor sit amet, consectetur adipiscing elit. Cras lobortis sem dui. "
        b"Morbi at magna quis ligula faucibus\nconsectetur feugiat at purus. Sed nec lorem nibh. Nam vel "
        b"libero odio. Vivamus tempus non enim egestas pretium.\nVestibulum turpis arcu, maximus nec libero "
        b"quis, imperdiet suscipit purus. Vestibulum blandit quis lacus non\nsollicitudin. Nullam non "
        b"convallis dui, et aliquet risus. Sed accumsan ullamcorper vehicula. Proin non urna facilisis,"
        b"\ncondimentum eros quis, suscipit purus. Morbi euismod imperdiet neque fermentum dictum. Integer "
        b"aliquam, erat sit\namet fringilla tempus, mauris ligula blandit sapien, et varius sem mauris eu "
        b"diam. Sed fringilla neque est, in laoreet\nfelis tristique in. Donec luctus velit a posuere "
        b"posuere. Suspendisse sodales pellentesque quam.\n",
    }

    scanner_event = run_test_scan(
        mocker=mocker,
        scan_class=ScanUnderTest,
        fixture_path=Path(__file__).parent / "fixtures/test_text.webp",
        options=(
            {"split_words": False, "remove_formatting": False, "create_thumbnail": True}
        ),
    )

    TestCase.maxDiff = None

    # Output string formatting may result in slightly different results.
    # Comparing similarity to the 99% percentile is good enough.
    similarity = difflib.SequenceMatcher(
        None, test_scan_event["string_text"], scanner_event["string_text"]
    ).ratio()
    assert similarity > 0.99

    # Ensure the thumbnail conversion works properly.
    TestCase().assertEqual(
        test_scan_event["base64_thumbnail"], scanner_event["base64_thumbnail"]
    )
