/** @type {import('tailwindcss').Config} */
module.exports = {
    content: [
        "./node_modules/preline/dist/*.js",
        "../../**/*.{html,js}",
    ],
    safelist: [
        'alert-error',
        'alert-warning',
        'alert-attention',
        'alert-note',
        'alert-success',
    ],
    theme: {
        fontFamily: {
            'sans': ['Nunito Sans', 'sans-serif']
        }
    },
    darkMode:
        'media',
    plugins:
        [
            require('@tailwindcss/forms'),
            require('preline/plugin')
        ]
}
