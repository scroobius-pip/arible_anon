const functions = require('@google-cloud/functions-framework');
const DLP = require('@google-cloud/dlp');
const dlp = new DLP.DlpServiceClient();
const { Buffer } = require('node:buffer')

const hexToRgb = hex =>
    hex.replace(/^#?([a-f\d])([a-f\d])([a-f\d])$/i
        , (m, r, g, b) => '#' + r + r + g + g + b + b)
        .substring(1).match(/.{2}/g)
        .map(x => parseInt(x, 16) / 255)

functions.http('redact', async (req, res) => {
    const authHeader = req.get('Authorization');
    const expectedAuth = process.env.ARIBLE_APP_AUTH;

    // Check if the Authorization header matches the expected value
    if (authHeader !== expectedAuth) {
        res.status(401).send('INVALID AUTH')

    }
    const images = req.body.images
    const DEFAULT_INFO_TYPES = ['EMAIL_ADDRESS,PHONE_NUMBER']
    const selectedInfoTypes = (req.body.selected_types ?? DEFAULT_INFO_TYPES).flatMap(s => s.split(',')).map(name => ({ name }))
    const [red, green, blue] = req.body.color ? hexToRgb(req.body.color) : [0, 0, 0]
    const redactAllText = !!req.body.redact_all
    const redactRequest = async (image) => {
        const [b64header, data] = image.split(",")
        const request = {
            parent: 'projects/arible/locations/global',
            byteItem: {
                type: "IMAGE",
                data
            },
            imageRedactionConfigs: redactAllText ?
                [{
                    redactAllText,
                    redactionColor: {
                        red, green, blue
                    }
                }] :
                selectedInfoTypes.map(infoType => ({
                    infoType,
                    redactionColor: {
                        red, green, blue
                    }
                })),
            inspectConfig: {
                infoTypes: selectedInfoTypes
            }
        }

        const [response] = await dlp.redactImage(request)

        return `${b64header},${Buffer.from(response.redactedImage).toString('base64')}`
    }

    const redactedImages = await Promise.all(images.map(redactRequest))

    res.json(
        {
            fields: [
                {
                    "name": "redacted_images",
                    "title": "Here are your redacted images",
                    "type": "Image",
                    "value": redactedImages
                }
            ]
        }
    )
});
