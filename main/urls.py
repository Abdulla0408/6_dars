from django.urls import path
from . import views


urlpatterns = [
    # Authentication
    path('', views.index, name='index'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),

    #Quiz
    path('quiz/list/', views.list_quiz, name='quiz_list'),
    path('quiz/<int:pk>/', views.read_quiz, name='read_quiz'),
    path('quiz/create/', views.create_quiz, name='create_quiz'),
    path('quiz/delete/<int:pk>/', views.delete_quiz, name='delete_quiz'),
]