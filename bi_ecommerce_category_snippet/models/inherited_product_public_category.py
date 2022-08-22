from odoo import api, fields, models, _

class ProductPublicCategory(models.Model):
    _inherit = "product.public.category"

    description = fields.Text(string='Description')

