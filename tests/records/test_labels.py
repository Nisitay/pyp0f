from pyp0f.records.labels import Label


def test_label():
    assert Label.parse("g:o:n:f") == Label(
        is_generic=True, name="n", os_class="o", flavor="f"
    )

    assert Label.parse("s:!::").is_user_app
