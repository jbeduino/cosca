import tempfile
import os
import json
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle,Spacer, Flowable
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor
from output_handler import OutputHandler

class ModernSeparator(Flowable):
    def __init__(self, width, height=1):
        Flowable.__init__(self)
        self.width = width
        self.height = height

    def draw(self):
        self.canv.setStrokeColor(HexColor("#333333"))
        self.canv.setLineWidth(self.height)
        self.canv.line(0, 0, self.width, 0)

class CustomOutputHandler(OutputHandler):
    """
    Creates a pdf report using a json file as reference
    """

    def remove_prefix_from_path(self, file_path, prefix):
        if file_path.startswith(prefix):
            return file_path[len(prefix):].lstrip(os.sep)
        return file_path

    def write_pdf(self,pdf_file,json_file):
        with open(json_file, 'r', encoding='utf-8') as file:
            json_data = json.load(file)
        pdf = SimpleDocTemplate(pdf_file, pagesize=letter)
        elements = []
        styles = getSampleStyleSheet()

        modern_style = ParagraphStyle(
            'Modern',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=12,
            leading=15,
            spaceAfter=12,
            textColor='#333333'
        )

        note_style = ParagraphStyle(
            'Modern',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=8,
            leading=12,
            spaceAfter=12,
            textColor='#333333'
        )

        title_style_1 = ParagraphStyle(
            'Title',
            parent=styles['Title'],
            fontName='Helvetica-Bold',
            fontSize=24,
            leading=28,
            spaceAfter=20,
            textColor='#000000'
        )

        title_style_2 = ParagraphStyle(
            'Title',
            parent=styles['Title'],
            fontName='Helvetica-Bold',
            fontSize=18,
            leading=28,
            spaceAfter=20,
            textColor='#000000'
        )

        title = Paragraph(json_data["title"], title_style_1)
        elements.append(title)
        elements.append(Spacer(1, 0.2*inch))
        paragraph2 = Paragraph(f'{json_data["date"]} - {json_data["time"]}', modern_style)
        elements.append(paragraph2)

        elements.append(ModernSeparator(width=6*inch, height=1))
        elements.append(Spacer(1, 12))
        title_summary = Paragraph("Findings summary", title_style_2)
        elements.append(Spacer(1, 0.2*inch))
        elements.append(title_summary)
        data = json_data["table"]
        table = Table(data)
        table_style = TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f2f2f2")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor("#333333")),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor("#dddddd")),
        ])
        table.setStyle(table_style)
        elements.append(table)

        elements.append(Spacer(1, 0.2*inch))
        paragraph_end = Paragraph('For more information, visit https://github.com/jbeduino/cosca', note_style)
        elements.append(paragraph_end)
        pdf.build(elements)

    def create_json_file(self, filename):
        data = {
            "title": "Combo Scanner Report",
            "date": datetime.now().strftime('%Y-%m-%d'),
            "time": datetime.now().strftime('%H:%M:%S'),
            "table": [['Target','Scanner', 'Info', 'Low', 'Medium', 'High', 'Critical', 'Unknown']]
        }
        with open(filename, 'w', encoding='utf-8') as json_file:
            json.dump(data, json_file, ensure_ascii=False, indent=4)

    def add_row_to_json(self, json_file, new_row):
        if not os.path.exists(json_file):
            self.create_json_file(json_file)
        try:
            with open(json_file, 'r', encoding='utf-8') as file:
                data = json.load(file)
            if "table" in data:
                data["table"].append(new_row)
            else:
                self.logger.error("Table not found in the JSON data.")
                return
            with open(json_file, 'w', encoding='utf-8') as file:
                json.dump(data, file, ensure_ascii=False, indent=4)
            self.logger.debug("Row added successfully.")
        except FileNotFoundError:
            self.logger.error("The file was not found.")
        except json.JSONDecodeError:
            self.logger.error("Error decoding JSON from the file.")

    def setup(self):
        self.tmp_dir = tempfile.gettempdir()
        self.parser.add_argument(
            "--pdf_output_folder", help="Folder to place the pdf file", default=self.tmp_dir)
        self.parser.add_argument(
            "--pdf_file_prefix", help="Filename prefix for the pdf file", default="")
        self.args = self.parser.parse_args()

    def process_files(self, report_path, target, scanner, aux_args):
        self.logger.debug("Generating output...")
        json_name = f"{self.args.pdf_file_prefix}{os.path.normpath(self.remove_prefix_from_path(report_path, self.tmp_dir)).split(os.sep)[0]}.json"
        json_path = f"{self.args.pdf_output_folder}{os.sep}{json_name}"
        pdf_name = f"{self.args.pdf_file_prefix}{os.path.normpath(self.remove_prefix_from_path(report_path, self.tmp_dir)).split(os.sep)[0]}.pdf"
        pdf_path = f"{self.args.pdf_output_folder}{os.sep}{pdf_name}"
        self.add_row_to_json(json_path, [target,scanner]+aux_args["json_findings"])
        self.write_pdf(pdf_path,json_path)
        self.logger.info("PDF report: file://%s", pdf_path)
        return {self.name : [{"pdf_summary": pdf_path},{"json_summary": json_path}]}

    def process_stdout(self, stdout):
        pass