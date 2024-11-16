from urllib.parse import urlparse
from urllib.request import urlretrieve

from app import sendgrid_client, openAI_client
from sendgrid.helpers.mail import Mail, From
from flask import abort


def is_internal_url(url):
    domains = [
        "localhost",
        "127.0.0.1:8080",
        "winning-doe-lovely.ngrok-free.app",
        "beacon-xdylan03x.pythonanywhere.com"
    ]
    parsed_url = urlparse(url)
    if not parsed_url.scheme:
        return True
    if parsed_url.netloc in domains:
        return True
    return False


def validate_next_url(url: str):
    if url:
        if is_internal_url(url):
            return url
        else:
            return f"/external-redirect?next={url}"
    return False


def clean_args(query_parameters: dict, args_to_remove=[]) -> dict:
    cleaned_arguments = query_parameters.copy()
    for argument in args_to_remove:
        try:
            cleaned_arguments.pop(argument)
        except KeyError:
            pass
    return cleaned_arguments


def send_email(subject: str, body: str, recipients: list[str], preheader="", sender="xdylan2003x@gmail.com", sender_name="Beacon", template_id="d-334e2c1f69454e18b514c93ea8667289"):
    message = Mail(from_email=From(sender, sender_name), to_emails=recipients)
    message.dynamic_template_data = {
        'body': body,
        'subject': subject,
        'preheader': preheader
    }
    message.template_id = template_id
    try:
        sendgrid_client.send(message)
    except Exception as e:
        print("Error: {0}".format(e))


def order_list(choices: list, first_item: str) -> list:
    if first_item in choices:
        choices.remove(first_item)
    choices.insert(0, first_item)
    return choices


def verify_tab_request(tabs: list[str], requested_tab: str):
    if requested_tab and requested_tab not in tabs:
        abort(404)


def transcribe_audio(audio_url, audio_file_path):
    urlretrieve(audio_url, audio_file_path)
    try:
        with open(audio_file_path, 'rb') as audio_file:
            trans = openAI_client.audio.transcriptions.create(model="whisper-1", file=audio_file)
        return trans.text
    except Exception:
        return ""


def summarize_audio(transcription):
    completion = openAI_client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": "You are a bot designed to summarize an audio transcription between a patient and a phone attendant. Create a summry of the call in less than 3 sentences and then create a list of action items needed by whoever handles the call."},
            {"role": "user", "content": transcription}
        ]
    )

    return completion.choices[0].message.content
