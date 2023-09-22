from pyp0f.database.labels import Label


def test_label():
    assert Label.parse("s:unix:Linux:3.11 and newer") == Label(
        is_generic=False, name="Linux", os_class="unix", flavor="3.11 and newer"
    )

    assert Label.parse("s:!::").is_user_app
