# -*- coding: utf-8 -*-
# Part of BrowseInfo. See LICENSE file for full copyright and licensing details.


{
    'name': 'Product Category Snippet Builder',
    'version': '15.0.0.1',
    'category': 'ecommerce',
    'license': 'OPL-1',
    'summary': 'Build custom snippet for website snippet builder for website easy snippet designer for website e-commerce snippet builder for ecommerce snippet designer website category snippet builder for product category snippets ecommerce category snippet builder shop',
    "description": """
       eCommerce Category Snippets, Here you can find the different layout of category snippet styles
    """,
    'author': 'BrowseInfo',
    'website': 'https://www.browseinfo.in',
    'price': 20,
    'currency': "EUR",
    'depends': ['website', 'website_sale'],
    'data': [
        'views/product_public_category_templates.xml',
        'views/product_public_category_views.xml',
            ],
    'qweb': [],
    'installable': True,
    'auto_install': False,
    'live_test_url':'https://youtu.be/H5G84C8ANVQ',
    "images":['static/description/Banner.png'],
    'assets':{
        'web.assets_frontend':[
            'bi_ecommerce_category_snippet/static/src/scss/owl.carousel.min.css',
            'bi_ecommerce_category_snippet/static/src/scss/bi_ecommerce_category_snippet_frontend.scss',
            'bi_ecommerce_category_snippet/static/src/js/owl.carousel.js',
            'bi_ecommerce_category_snippet/static/src/js/bi_ecommerce_category_snippet_frontend.js',
        ],
        'website.assets_editor':[
            'bi_ecommerce_category_snippet/static/src/scss/bi_ecommerce_category_snippet_editor.scss',
            'bi_ecommerce_category_snippet/static/src/js/bi_ecommerce_category_snippet_editor.js',
        ]
    },
}
