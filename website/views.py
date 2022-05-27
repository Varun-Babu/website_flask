from flask import Blueprint, render_template
from flask_login import login_required, current_user


views = Blueprint('views', __name__)


@views.route('/')
def home():
    return render_template("home.html")


@views.route('/about')
def about():
    return render_template("about.html")


# @views.route("/ml")
# @login_required
# def ml():
#     return render_template("ml.html")


@views.route("/team")
def team():
    return render_template("team.html")


@views.route("/contact")
def contact():
    return render_template("contact.html")


@views.route("/thankyou")
def thankyou():
    return render_template("thankyou.html")
