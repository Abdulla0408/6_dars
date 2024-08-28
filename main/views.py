from django.shortcuts import render, redirect, get_object_or_404
from .models import Quiz
from django.contrib.auth import authenticate, login as auth_login
from django.contrib.auth import logout as auth_logout 
from django.contrib.auth.decorators import login_required
from .forms import QuizForm


def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            auth_login(request, user)
            return redirect('index')
        else:
            error = "Foydalanuvchi nomi yoki parol noto'g'ri."
            return render(request, 'login.html', {'error': error})
    return render(request, 'login.html')


def logout_view(request):
    auth_logout(request)
    return redirect('login')


def is_admin(user):
    return user.is_authenticated and user.is_staff


def admin_required(view_func):
    def wrapper(request, *args, **kwargs):
        if is_admin(request.user):
            return view_func(request, *args, **kwargs)
        else:
            return redirect('login')
    return wrapper


def index(request):
    return render(request, 'base.html')


#Quiz----------------------------------------------------------------------------------
def list_quiz(request):
    quizzes = Quiz.objects.all()
    return render(request, 'quiz/quiz_list.html', {'quizzes': quizzes})


def read_quiz(request, pk):
    quiz = get_object_or_404(Quiz, pk=pk)
    return render(request, 'quiz/read_quiz.html', {'quiz': quiz})

def create_quiz(request):
    if request.method == 'POST':
        form = QuizForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('index')
    else:
        form = QuizForm()
    return render(request, 'quiz/create_quiz.html', {'form': form})

def delete_quiz(request, pk):
    quiz = get_object_or_404(Quiz, pk=pk)
    quiz.delete()
    return redirect('/')
