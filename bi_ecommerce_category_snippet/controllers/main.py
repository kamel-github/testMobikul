import odoo
from odoo import http
from odoo.http import request

class EcommerceCategory(http.Controller):

    @http.route('/category/snippet/render', type='json', auth="public", website=True)
    def eCommerceCategory(self, classList=False, template=False, style_id=False, **kw):
        if classList and template:
            website = request.env['website'].get_current_website()
            categories = request.env['product.public.category'].sudo().search([("parent_id","=",False),("website_id","in",(False, website.id))])
            isimage = 'image' in classList
            isdescription = 'description' in classList
            isproductcount = 'product_count' in classList
            values = {
                'isimage': isimage,
                'isdescription': isdescription,
                'isproductcount': isproductcount,
                'style_id': style_id,
                'categories': categories,
            }
            response = http.Response(template="bi_ecommerce_category_snippet."+template,qcontext=values)
            return response.render()
        return False
