from django.views.generic.list import ListView
from django.views.generic import TemplateView
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.shortcuts import render

from app.models import *


class RevisionListView(ListView):
    model = Revision
    queryset = Revision.objects.filter(is_loaded=True)


class FunctionListView(TemplateView):
    template_name = 'app/function_list.html'

    def get(self, request, *args, **kwargs):
        id = kwargs.get('pk')
        print(id)
        revision = Revision.objects.get(pk=id)
        functions = revision.function_set.all()

        num_neutral_functions = functions.filter(is_vulnerable=False).count()
        num_vulnerable_functions = functions.filter(is_vulnerable=True).count()

        page = request.GET.get('page')

        paginator = Paginator(functions, 25)
        try:
            functions = paginator.page(page)
        except PageNotAnInteger:
            functions = paginator.page(1)
        except EmptyPage:
            functions = paginator.page(paginator.num_pages)

        print(len(functions))

        context = {
            'object_list': functions,
            'num_neutral_functions': num_neutral_functions,
            'num_vulnerable_functions': num_vulnerable_functions,
            'object': revision
        }

        return render(request, self.template_name, context)
